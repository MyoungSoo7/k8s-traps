import textwrap

import pytest

from k8s_traps import audit, load


def run(yaml_text: str, trap: str):
    return audit(load([textwrap.dedent(yaml_text)]), [trap])


def deploy(name="app", ns="prod", pod_extra="", container_extra="", replicas=1, template_meta=""):
    return textwrap.dedent(f"""
    apiVersion: apps/v1
    kind: Deployment
    metadata: {{name: {name}, namespace: {ns}}}
    spec:
      replicas: {replicas}
      template:
        metadata:
          labels: {{app: {name}}}
{textwrap.indent(textwrap.dedent(template_meta), ' ' * 10)}
        spec:
{textwrap.indent(textwrap.dedent(pod_extra), ' ' * 10)}
          containers:
          - name: main
            image: example/app:1
{textwrap.indent(textwrap.dedent(container_extra), ' ' * 12)}
    """)


def service(name, ns="prod", labels="{}", selector="{app: x}", ports="[{name: http, port: 80}]"):
    return textwrap.dedent(f"""
    ---
    apiVersion: v1
    kind: Service
    metadata: {{name: {name}, namespace: {ns}, labels: {labels}}}
    spec: {{selector: {selector}, ports: {ports}}}
    """)


# ---------------------------------------------------------------- T01

def test_t01_known_collision():
    found = run(deploy() + service("server"), "T01")
    assert len(found) == 1 and "SERVER_PORT" in found[0].message and found[0].severity == "medium"


def test_t01_referenced_variable():
    extra = "env:\n- {name: DB, value: '$(PAYMENTS_SERVICE_HOST)'}"
    found = run(deploy(container_extra=extra) + service("payments"), "T01")
    assert len(found) == 1 and found[0].severity == "high"


def test_t01_same_name_is_medium():
    found = run(deploy(name="ledger") + service("ledger"), "T01")
    assert [f.severity for f in found] == ["low"]


def test_t01_unnamespaced_inputs_do_not_mix():
    # two separate `helm template` renders without namespaces: different namespaces once applied
    plain = [textwrap.dedent(deploy()).replace("namespace: prod", "namespace: null"),
             textwrap.dedent(service("server")).replace("namespace: prod", "namespace: null")]
    assert audit(load(plain), ["T01"]) == []
    assert len(audit(load(["\n".join(plain)]), ["T01"])) == 1


def test_t01_disabled_links_is_clean():
    assert run(deploy(pod_extra="enableServiceLinks: false") + service("server"), "T01") == []


def test_t01_explicit_env_wins():
    extra = "env:\n- {name: SERVER_PORT, value: '8080'}"
    assert run(deploy(container_extra=extra) + service("server"), "T01") == []


def test_t01_other_namespace_and_headless_are_clean():
    other = service("server", ns="other")
    headless = service("kafka").replace("spec: {", "spec: {clusterIP: None, ")
    assert run(deploy() + other + headless, "T01") == []


# ---------------------------------------------------------------- T02

SM = """
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: app, namespace: prod}
spec:
  selector: {matchLabels: {app: app}}
  endpoints: [{port: http}]
"""


def test_t02_selects_pod_labels():
    found = run(service("app", selector="{app: app}") + SM, "T02")
    assert len(found) == 1 and "pod selector" in found[0].message and found[0].severity == "high"


def test_t02_port_name_missing():
    svc = service("app", labels="{app: app}", ports="[{port: 80}]")
    found = run(svc + SM, "T02")
    assert len(found) == 1 and "not a named port" in found[0].message


def test_t02_correct_is_clean():
    assert run(service("app", labels="{app: app}") + SM, "T02") == []


def test_t02_no_service_in_input_is_silent():
    assert run(SM, "T02") == []


# ---------------------------------------------------------------- T03

def test_t03_missing_policy():
    found = run(deploy(), "T03")
    assert len(found) == 1 and found[0].object == "namespace prod"


def test_t03_policy_present():
    policy = "\n---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: deny, namespace: prod}\nspec: {podSelector: {}}\n"
    assert run(deploy() + policy, "T03") == []


# ---------------------------------------------------------------- T04

SUBPATH_POD = """
volumes:
- name: site
  configMap: {name: site}
"""
SUBPATH_MOUNT = """
volumeMounts:
- {name: site, mountPath: /usr/share/nginx/html/index.html, subPath: index.html}
"""


def test_t04_subpath_configmap():
    found = run(deploy(pod_extra=SUBPATH_POD, container_extra=SUBPATH_MOUNT), "T04")
    assert len(found) == 1 and "subPath" in found[0].message


def test_t04_checksum_annotation_is_clean():
    meta = "annotations: {checksum/config: abc}"
    assert run(deploy(pod_extra=SUBPATH_POD, container_extra=SUBPATH_MOUNT, template_meta=meta), "T04") == []


def test_t04_whole_volume_is_clean():
    mount = "volumeMounts:\n- {name: site, mountPath: /usr/share/nginx/html}"
    assert run(deploy(pod_extra=SUBPATH_POD, container_extra=mount), "T04") == []


# ---------------------------------------------------------------- T05

def cloudflared(rules: str) -> str:
    return f"""
    apiVersion: v1
    kind: ConfigMap
    metadata: {{name: tunnel, namespace: edge}}
    data:
      config.yaml: |
        tunnel: abc
        ingress:
{textwrap.indent(textwrap.dedent(rules), ' ' * 10)}
          - service: http_status:404
    """


def test_t05_shared_nodeport():
    rules = """
    - {hostname: n8n.example.com, service: 'http://192.168.0.11:31463'}
    - {hostname: payment-webhook.example.com, service: 'http://192.168.0.11:31463'}
    """
    found = run(cloudflared(rules), "T05")
    assert len(found) == 1 and "payment-webhook.example.com" in found[0].message


def test_t05_www_alias_is_clean():
    rules = """
    - {hostname: example.com, service: 'http://landing.web.svc:80'}
    - {hostname: www.example.com, service: 'http://landing.web.svc:80'}
    """
    assert run(cloudflared(rules), "T05") == []


def test_t05_ingress_rules():
    ing = """
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata: {name: web, namespace: prod}
    spec:
      rules:
      - host: a.example.com
        http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}]}
      - host: b.example.com
        http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}]}
    """
    assert len(run(ing, "T05")) == 1


# ---------------------------------------------------------------- T06

SOFT = """
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm: {topologyKey: kubernetes.io/hostname, labelSelector: {matchLabels: {app: app}}}
"""
HARD_SPREAD = """
topologySpreadConstraints:
- {maxSkew: 1, topologyKey: kubernetes.io/hostname, whenUnsatisfiable: DoNotSchedule, labelSelector: {matchLabels: {app: app}}}
"""


def test_t06_soft_only():
    found = run(deploy(replicas=3, pod_extra=SOFT), "T06")
    assert [f.severity for f in found] == ["medium"]


def test_t06_nothing_is_low():
    assert [f.severity for f in run(deploy(replicas=3), "T06")] == ["low"]


@pytest.mark.parametrize("extra,replicas", [(HARD_SPREAD, 3), (SOFT, 1)])
def test_t06_clean(extra, replicas):
    assert run(deploy(replicas=replicas, pod_extra=extra), "T06") == []


# ---------------------------------------------------------------- T07

def test_t07_env_literal_and_value_not_leaked():
    extra = "env:\n- {name: DB_PASSWORD, value: hunter2hunter2}"
    found = run(deploy(container_extra=extra), "T07")
    assert len(found) == 1 and "hunter2" not in found[0].message


def test_t07_configmap_key():
    cm = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: prod}\ndata: {API_KEY: sk-live-abc123}\n"
    assert len(run(cm, "T07")) == 1


@pytest.mark.parametrize("name,value", [
    ("DB_PASSWORD_FILE", "/run/secrets/db"),
    ("TOKEN_URL", "https://auth.example.com/token"),
    ("JWT_SECRET", "$(JWT_SECRET_FROM_ENV)"),
    ("API_KEY", ""),
    ("DISABLE_ADMIN_TOKEN", "false"),
    ("TOKEN_TTL_SECONDS", "3600"),
])
def test_t07_non_secrets(name, value):
    extra = f"env:\n- {{name: {name}, value: '{value}'}}"
    assert run(deploy(container_extra=extra), "T07") == []


def test_t07_secret_ref_is_clean():
    extra = "env:\n- name: DB_PASSWORD\n  valueFrom: {secretKeyRef: {name: db, key: password}}"
    assert run(deploy(container_extra=extra), "T07") == []


# ---------------------------------------------------------------- misc

def test_unknown_trap_id():
    with pytest.raises(ValueError):
        audit(load(["{}"]), ["T99"])


def test_parse_error_is_reported_not_raised():
    bundle = load(["a: [unclosed"])
    assert bundle.errors and bundle.objects == []


def test_cronjob_and_list_are_walked():
    doc = """
    apiVersion: v1
    kind: List
    items:
    - apiVersion: batch/v1
      kind: CronJob
      metadata: {name: nightly, namespace: jobs}
      spec:
        schedule: '0 3 * * *'
        jobTemplate:
          spec:
            template:
              spec:
                containers:
                - name: c
                  image: x
                  env: [{name: GITHUB_TOKEN, value: ghp_abcdef}]
    """
    assert [f.trap for f in run(doc, "T07")] == ["T07"]
