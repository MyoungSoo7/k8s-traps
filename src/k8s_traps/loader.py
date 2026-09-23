"""Parse multi-document Kubernetes YAML into plain dicts and index them."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

# Kinds whose pod template we can inspect, and where that template lives.
_POD_SPEC_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}

# Objects without metadata.namespace (typical of `helm template` output) land in
# whatever namespace they are applied to. We assume that is one namespace per
# input (one file / one render), never one namespace shared by all inputs.
UNSPECIFIED_NS = "(unspecified)"
_INPUT = "__k8s_traps_input__"


def dig(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


@dataclass
class Workload:
    obj: dict
    pod_spec: dict

    @property
    def kind(self) -> str:
        return self.obj.get("kind", "")

    @property
    def name(self) -> str:
        return dig(self.obj, "metadata", "name") or ""

    @property
    def namespace(self) -> str:
        return namespace_of(self.obj)

    @property
    def containers(self) -> list[dict]:
        return list(self.pod_spec.get("containers") or []) + list(self.pod_spec.get("initContainers") or [])


@dataclass
class Bundle:
    objects: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def of_kind(self, *kinds: str) -> list[dict]:
        return [o for o in self.objects if o.get("kind") in kinds]

    def workloads(self) -> list[Workload]:
        result = []
        for obj in self.objects:
            path = _POD_SPEC_PATHS.get(obj.get("kind", ""))
            spec = dig(obj, *path) if path else None
            if isinstance(spec, dict):
                result.append(Workload(obj, spec))
        return result


def namespace_of(obj: dict) -> str:
    ns = dig(obj, "metadata", "namespace")
    if ns:
        return ns
    return f"{UNSPECIFIED_NS} input #{obj[_INPUT] + 1}" if _INPUT in obj else UNSPECIFIED_NS


def ref(obj: dict) -> str:
    """Human-readable object reference: Kind/namespace/name."""
    ns = dig(obj, "metadata", "namespace")
    name = dig(obj, "metadata", "name") or "?"
    return f"{obj.get('kind', '?')}/{ns + '/' if ns else ''}{name}"


# Pseudo-kind for a cloudflared tunnel config (not a Kubernetes object, but it
# routes hostnames to in-cluster backends, which is what trap T05 inspects).
CLOUDFLARED = "cloudflared-config"


def _is_cloudflared(doc: Any) -> bool:
    return (isinstance(doc, dict) and not doc.get("kind") and isinstance(doc.get("ingress"), list)
            and any(isinstance(r, dict) and "service" in r for r in doc["ingress"]))


def _flatten(doc: Any) -> Iterable[dict]:
    if not isinstance(doc, dict):
        return
    kind = doc.get("kind") or ""
    if kind == "List" or (kind.endswith("List") and isinstance(doc.get("items"), list)):
        for item in doc.get("items") or []:
            yield from _flatten(item)
        return
    if _is_cloudflared(doc):
        yield {"kind": CLOUDFLARED, "metadata": {"name": "cloudflared"}, "ingress": doc["ingress"]}
        return
    if kind:
        yield doc
    # cloudflared is usually deployed with its config inside a ConfigMap.
    if kind == "ConfigMap":
        for key, value in (doc.get("data") or {}).items():
            if isinstance(value, str) and "ingress:" in value:
                try:
                    inner = yaml.safe_load(value)
                except yaml.YAMLError:
                    continue
                if _is_cloudflared(inner):
                    yield {"kind": CLOUDFLARED, "ingress": inner["ingress"],
                           "metadata": {"name": f"{dig(doc, 'metadata', 'name')}:{key}",
                                        "namespace": dig(doc, "metadata", "namespace")}}


def load(texts: Iterable[str]) -> Bundle:
    bundle = Bundle()
    for i, text in enumerate(texts):
        try:
            for doc in yaml.safe_load_all(text):
                for obj in _flatten(doc):
                    obj[_INPUT] = i
                    bundle.objects.append(obj)
        except yaml.YAMLError as error:
            bundle.errors.append(f"input #{i + 1}: YAML parse error: {error}")
    return bundle
