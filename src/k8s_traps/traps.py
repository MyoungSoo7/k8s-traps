"""The trap catalog and the checks behind it.

Every trap here comes from an incident on a real (homelab) K3s cluster. They are
deliberately *not* generic best-practice lint — tools like Kubescape, kube-linter
and Trivy already cover that well. These are the failures that pass those tools
and still break production, usually silently.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Callable
from urllib.parse import urlparse

from .loader import CLOUDFLARED, Bundle, dig, namespace_of, ref

DOCS = "https://github.com/MyoungSoo7/k8s-traps/blob/main/docs/traps.md"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Trap:
    id: str
    title: str
    severity: str  # default severity; individual findings may be lower
    summary: str
    incident: str
    fix: str

    @property
    def docs(self) -> str:
        return f"{DOCS}#{self.id.lower()}"


@dataclass
class Finding:
    trap: str
    severity: str
    object: str
    message: str
    fix: str
    docs: str

    def to_dict(self) -> dict:
        return asdict(self)


TRAPS: dict[str, Trap] = {t.id: t for t in [
    Trap(
        "T01", "Service-link env vars collide with the app's own settings", "high",
        "Kubernetes injects <SERVICE>_PORT=tcp://10.x.x.x:port (and friends) into every pod in the namespace. "
        "If an app reads a variable with that name as a number or hostname, it crashes or misroutes.",
        "A service named like an application's port variable made the pods boot with PORT set to "
        "'tcp://…' instead of a number; the app died on startup and nothing in the manifest looked wrong.",
        "Set `enableServiceLinks: false` on the pod spec (apps should use DNS names anyway), "
        "or set the variable explicitly in the container env, which takes precedence.",
    ),
    Trap(
        "T02", "ServiceMonitor selects nothing — metrics silently missing", "high",
        "ServiceMonitor.spec.selector matches Service *metadata.labels*, not the pod labels in "
        "Service.spec.selector, and endpoints[].port must be a *named* Service port. Get either wrong "
        "and Prometheus scrapes nothing, with no error anywhere.",
        "A ServiceMonitor copied the pod selector; the target never appeared and a dashboard showed "
        "'no data' for 75 days before anyone noticed.",
        "Put the ServiceMonitor's labels on the Service's metadata.labels and give the Service port a "
        "`name:` that matches endpoints[].port. Verify with the Prometheus /targets page, not the manifest.",
    ),
    Trap(
        "T03", "Namespace has workloads but no NetworkPolicy", "medium",
        "Without any NetworkPolicy, every pod in the cluster can reach every pod in this namespace.",
        "NetworkPolicies turned out to be the one runtime control that GitOps self-heal did not undo — "
        "and the namespaces without one were the ones exposed.",
        "Add a default-deny ingress policy for the namespace, then allow the flows you actually need. "
        "(Only meaningful if your CNI enforces NetworkPolicy; flannel alone does not, k3s ships an enforcer.)",
    ),
    Trap(
        "T04", "ConfigMap/Secret mounted with subPath never updates", "low",
        "Files mounted via subPath are copied once at container start. Editing the ConfigMap or Secret "
        "changes nothing in the running pod — and GitOps will report the change as applied.",
        "A homepage served from a subPath-mounted ConfigMap kept serving the old page after every "
        "'successful' sync until someone restarted the deployment by hand.",
        "Mount the whole volume (no subPath) if the app can re-read files, or add a checksum/config "
        "annotation to the pod template so a change triggers a rollout.",
    ),
    Trap(
        "T05", "Two hostnames route to the same backend", "medium",
        "When a retired app's route is left pointing at a port that another app now uses, the old "
        "hostname does not 404 — it serves the other app with HTTP 200, so health checks stay green.",
        "A payment-webhook hostname and a workflow tool shared one NodePort in the tunnel config; the "
        "webhook URL happily returned the workflow tool's login page.",
        "Decide per hostname whether it is still needed. Remove dead routes together with their DNS "
        "record. Prefer routing to a Service DNS name over a node IP + NodePort.",
    ),
    Trap(
        "T06", "Replicas only *prefer* to spread", "medium",
        "preferredDuringScheduling anti-affinity and ScheduleAnyway topology spread are hints. When "
        "nodes are tight the scheduler packs replicas onto the same node, and one node loss takes "
        "the whole service down.",
        "17 of 30 pods of a 'highly available' namespace ended up on one node; its anti-affinity was soft.",
        "Use topologySpreadConstraints with whenUnsatisfiable: DoNotSchedule (or required anti-affinity) "
        "for services that must survive a node loss — and accept that they may go Pending when capacity is short.",
    ),
    Trap(
        "T07", "Secret value written in plain text", "high",
        "A password/token/key in container env `value:` or in a ConfigMap ends up in git, in "
        "`kubectl describe`, and in every backup — none of which are treated as secret stores.",
        "Recurring finding during manifest reviews; the values are never shown in this tool's output.",
        "Move the value into a Secret (ideally encrypted in git with SOPS or sealed-secrets) and reference "
        "it with valueFrom.secretKeyRef or envFrom.secretRef.",
    ),
]}


def _finding(trap_id: str, obj_ref: str, message: str, severity: str | None = None) -> Finding:
    trap = TRAPS[trap_id]
    return Finding(trap_id, severity or trap.severity, obj_ref, message, trap.fix, trap.docs)


# --------------------------------------------------------------------- T01

# Service names whose injected <NAME>_PORT is known to break a popular image or framework.
_KNOWN_COLLISIONS = {
    "server": "Spring Boot binds SERVER_PORT to server.port",
    "kafka": "Confluent Kafka images refuse to start when KAFKA_PORT is set",
    "jenkins": "the Jenkins image reads JENKINS_PORT",
}


def _env_prefix(service_name: str) -> str:
    return service_name.upper().replace("-", "_").replace(".", "_")


def _strings_in(container: dict) -> list[str]:
    out = [str(x) for x in (container.get("command") or []) + (container.get("args") or [])]
    out += [str(e.get("value")) for e in container.get("env") or [] if isinstance(e, dict) and e.get("value")]
    return out


def check_t01(bundle: Bundle) -> list[Finding]:
    findings = []
    services: dict[str, list[str]] = {}
    for svc in bundle.of_kind("Service"):
        if dig(svc, "spec", "clusterIP") == "None" or dig(svc, "spec", "type") == "ExternalName":
            continue  # headless / ExternalName services get no link env vars
        name = dig(svc, "metadata", "name")
        if name:
            services.setdefault(namespace_of(svc), []).append(name)

    for wl in bundle.workloads():
        if wl.pod_spec.get("enableServiceLinks") is False:
            continue
        labels = dig(wl.obj, "spec", "template", "metadata", "labels") or dig(wl.obj, "metadata", "labels") or {}
        own_names = {wl.name, labels.get("app"), labels.get("app.kubernetes.io/name")} - {None, ""}
        for svc_name in services.get(wl.namespace, []):
            prefix = _env_prefix(svc_name)
            var = f"{prefix}_PORT"
            # A variable set explicitly in a container's env wins over the injected one.
            exposed = [c for c in wl.containers
                       if var not in {e.get("name") for e in c.get("env") or [] if isinstance(e, dict)}]
            if not exposed:
                continue
            referencing = [c.get("name", "?") for c in exposed
                           if any(re.search(rf"\b{prefix}_(SERVICE_|PORT)", s) for s in _strings_in(c))]
            if referencing:
                findings.append(_finding(
                    "T01", f"{ref(wl.obj)} (container {', '.join(referencing)})",
                    f"Container references {prefix}_* but Service '{svc_name}' in the same namespace injects "
                    f"{var}=tcp://<ip>:<port> into this pod."))
            elif svc_name in _KNOWN_COLLISIONS:
                findings.append(_finding(
                    "T01", ref(wl.obj),
                    f"Service '{svc_name}' injects {var}=tcp://<ip>:<port> into this pod; "
                    f"{_KNOWN_COLLISIONS[svc_name]}. Matters if this workload runs that software.",
                    severity="medium"))
            elif svc_name in own_names:
                findings.append(_finding(
                    "T01", ref(wl.obj),
                    f"Service '{svc_name}' shares this app's name, so the pod gets {var}=tcp://<ip>:<port>. "
                    f"Harmless unless the app reads {var} — worth one grep.", severity="low"))
    return findings


# --------------------------------------------------------------------- T02

def _labels_match(selector: dict, labels: dict) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def check_t02(bundle: Bundle) -> list[Finding]:
    findings = []
    services = bundle.of_kind("Service")
    for sm in bundle.of_kind("ServiceMonitor"):
        selector = dig(sm, "spec", "selector", "matchLabels") or {}
        if not selector:
            continue  # matchExpressions-only / empty selectors are out of scope
        ns_sel = dig(sm, "spec", "namespaceSelector") or {}
        if ns_sel.get("any"):
            candidates = services
        else:
            names = set(ns_sel.get("matchNames") or [namespace_of(sm)])
            candidates = [s for s in services if namespace_of(s) in names]
        if not candidates:
            continue  # the Service is not part of the input; cannot judge

        matched = [s for s in candidates if _labels_match(selector, dig(s, "metadata", "labels") or {})]
        if not matched:
            by_pod_labels = [s for s in candidates
                             if _labels_match(selector, dig(s, "spec", "selector") or {})
                             or all((dig(s, "spec", "selector") or {}).get(k) == v for k, v in selector.items())]
            if by_pod_labels:
                findings.append(_finding(
                    "T02", ref(sm),
                    f"selector {selector} matches the *pod selector* of {ref(by_pod_labels[0])}, not its "
                    f"metadata.labels. The ServiceMonitor selects no Service and Prometheus scrapes nothing."))
            else:
                findings.append(_finding(
                    "T02", ref(sm),
                    f"No Service in the input carries labels {selector}. If the target Service is part of this "
                    f"input, nothing will be scraped.", severity="medium"))
            continue

        port_names = {p.get("name") for s in matched for p in dig(s, "spec", "ports") or [] if isinstance(p, dict)}
        for ep in dig(sm, "spec", "endpoints") or []:
            port = ep.get("port") if isinstance(ep, dict) else None
            if port and port not in port_names:
                findings.append(_finding(
                    "T02", ref(sm),
                    f"endpoint port '{port}' is not a named port on {ref(matched[0])} "
                    f"(named ports: {sorted(n for n in port_names if n) or 'none'}). That endpoint scrapes nothing."))
    return findings


# --------------------------------------------------------------------- T03

def check_t03(bundle: Bundle) -> list[Finding]:
    with_policy = {namespace_of(p) for p in bundle.of_kind("NetworkPolicy")}
    seen: dict[str, str] = {}
    for wl in bundle.workloads():
        ns = wl.namespace
        if ns in with_policy or ns in seen or ns.startswith("kube-"):
            continue
        seen[ns] = ref(wl.obj)
    return [_finding(
        "T03", f"namespace {ns}",
        f"Workloads such as {example} have no NetworkPolicy in this input. "
        f"(Judged from the input only — a policy applied elsewhere would not be seen.)")
        for ns, example in seen.items()]


# --------------------------------------------------------------------- T04

def check_t04(bundle: Bundle) -> list[Finding]:
    findings = []
    for wl in bundle.workloads():
        annotations = dig(wl.obj, "spec", "template", "metadata", "annotations") or {}
        if any(k.startswith("checksum/") for k in annotations):
            continue  # rollout-on-change is already wired up
        volumes = {v.get("name"): v for v in wl.pod_spec.get("volumes") or [] if isinstance(v, dict)}
        for c in wl.containers:
            for m in c.get("volumeMounts") or []:
                vol = volumes.get(m.get("name"))
                if not m.get("subPath") or not vol:
                    continue
                source = next((k for k in ("configMap", "secret", "projected") if k in vol), None)
                if source:
                    findings.append(_finding(
                        "T04", f"{ref(wl.obj)} (container {c.get('name', '?')})",
                        f"{m.get('mountPath')} is a subPath mount of {source} volume '{vol.get('name')}': "
                        f"updates will not reach the running pod until it restarts."))
    return findings


# --------------------------------------------------------------------- T05

def _routes(bundle: Bundle) -> list[tuple[str, str, str]]:
    """(hostname, normalized backend, source ref) for Ingresses and cloudflared configs."""
    routes = []
    for ing in bundle.of_kind("Ingress"):
        ns = namespace_of(ing)
        for rule in dig(ing, "spec", "rules") or []:
            host = rule.get("host") if isinstance(rule, dict) else None
            for path in dig(rule, "http", "paths") or []:
                svc = dig(path, "backend", "service") or {}
                port = (svc.get("port") or {}).get("number") or (svc.get("port") or {}).get("name")
                if host and svc.get("name"):
                    routes.append((host, f"svc {ns}/{svc['name']}:{port}", ref(ing)))
    for cf in bundle.of_kind(CLOUDFLARED):
        for rule in cf.get("ingress") or []:
            if not isinstance(rule, dict) or not rule.get("hostname") or not rule.get("service"):
                continue
            target = urlparse(rule["service"])
            backend = f"{target.hostname}:{target.port}" if target.hostname else rule["service"]
            routes.append((rule["hostname"], backend, ref(cf)))
    return routes


def _site(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def check_t05(bundle: Bundle) -> list[Finding]:
    by_backend: dict[str, list[tuple[str, str]]] = {}
    for host, backend, source in _routes(bundle):
        by_backend.setdefault(backend, []).append((host, source))
    findings = []
    for backend, entries in by_backend.items():
        sites = sorted({_site(h) for h, _ in entries})
        if len(sites) > 1:
            findings.append(_finding(
                "T05", entries[0][1],
                f"{', '.join(sites)} all route to {backend}. If any of these hostnames belonged to an app that "
                f"was retired or moved, it now serves this backend with HTTP 200 instead of failing."))
    return findings


# --------------------------------------------------------------------- T06

def check_t06(bundle: Bundle) -> list[Finding]:
    findings = []
    for obj in bundle.of_kind("Deployment", "StatefulSet"):
        replicas = dig(obj, "spec", "replicas")
        if not isinstance(replicas, int) or replicas < 2:
            continue
        spec = dig(obj, "spec", "template", "spec") or {}
        spread = spec.get("topologySpreadConstraints") or []
        anti = dig(spec, "affinity", "podAntiAffinity") or {}
        if any(c.get("whenUnsatisfiable") == "DoNotSchedule" for c in spread if isinstance(c, dict)):
            continue
        if anti.get("requiredDuringSchedulingIgnoredDuringExecution"):
            continue
        if spread or anti.get("preferredDuringSchedulingIgnoredDuringExecution"):
            findings.append(_finding(
                "T06", ref(obj),
                f"{replicas} replicas with only soft spreading (preferred anti-affinity / ScheduleAnyway). "
                f"Under capacity pressure they can all land on one node."))
        else:
            findings.append(_finding(
                "T06", ref(obj),
                f"{replicas} replicas with no spreading rule at all; placement is left to scheduler defaults, "
                f"which are soft.", severity="low"))
    return findings


# --------------------------------------------------------------------- T07

_SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)")
_NOT_SECRET_SUFFIX = re.compile(
    r"_(FILE|PATH|DIR|URL|URI|ENDPOINT|NAME|HEADER|TTL|EXPIRY|EXPIRES|SECONDS|MINUTES|TYPE|ENABLED|LENGTH|REF|KEY_ID|ID)$")


def _looks_secret(name: str, value) -> bool:
    key = re.sub(r"[.\-]", "_", str(name)).upper()
    if not _SECRET_NAME.search(key) or _NOT_SECRET_SUFFIX.search(key):
        return False
    if not isinstance(value, str) or not value.strip():
        return False
    v = value.strip()
    if v.lower() in {"true", "false", "yes", "no", "on", "off", "none", "null"} or v.isdigit():
        return False  # a flag or a number, e.g. DISABLE_ADMIN_TOKEN=false
    return not v.startswith(("$(", "${", "{{"))


def check_t07(bundle: Bundle) -> list[Finding]:
    findings = []
    for wl in bundle.workloads():
        for c in wl.containers:
            for e in c.get("env") or []:
                if isinstance(e, dict) and "value" in e and _looks_secret(e.get("name", ""), e.get("value")):
                    findings.append(_finding(
                        "T07", f"{ref(wl.obj)} (container {c.get('name', '?')})",
                        f"env {e['name']} has a literal value ({len(str(e['value']))} chars, not shown)."))
    for cm in bundle.of_kind("ConfigMap"):
        for key, value in (cm.get("data") or {}).items():
            if _looks_secret(key, value) and "\n" not in str(value).strip():
                findings.append(_finding(
                    "T07", ref(cm), f"key {key} holds a secret-looking value ({len(str(value))} chars, not shown)."))
    return findings


CHECKS: dict[str, Callable[[Bundle], list[Finding]]] = {
    "T01": check_t01, "T02": check_t02, "T03": check_t03, "T04": check_t04,
    "T05": check_t05, "T06": check_t06, "T07": check_t07,
}


def audit(bundle: Bundle, only: list[str] | None = None) -> list[Finding]:
    wanted = [t.upper() for t in only] if only else list(CHECKS)
    unknown = [t for t in wanted if t not in CHECKS]
    if unknown:
        raise ValueError(f"unknown trap id(s): {', '.join(unknown)}; known: {', '.join(CHECKS)}")
    findings = [f for t in wanted for f in CHECKS[t](bundle)]
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.trap, f.object))
