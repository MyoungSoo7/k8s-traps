# Trap catalog

Generated from `src/k8s_traps/traps.py` by `scripts/gen_docs.py` — edit the source, not this file.

<a id="t01"></a>
## T01 — Service-link env vars collide with the app's own settings

**Default severity:** high

Kubernetes injects <SERVICE>_PORT=tcp://10.x.x.x:port (and friends) into every pod in the namespace. If an app reads a variable with that name as a number or hostname, it crashes or misroutes.

**Where it came from.** A service named like an application's port variable made the pods boot with PORT set to 'tcp://…' instead of a number; the app died on startup and nothing in the manifest looked wrong.

**Fix.** Set `enableServiceLinks: false` on the pod spec (apps should use DNS names anyway), or set the variable explicitly in the container env, which takes precedence.

<a id="t02"></a>
## T02 — ServiceMonitor selects nothing — metrics silently missing

**Default severity:** high

ServiceMonitor.spec.selector matches Service *metadata.labels*, not the pod labels in Service.spec.selector, and endpoints[].port must be a *named* Service port. Get either wrong and Prometheus scrapes nothing, with no error anywhere.

**Where it came from.** A ServiceMonitor copied the pod selector; the target never appeared and a dashboard showed 'no data' for 75 days before anyone noticed.

**Fix.** Put the ServiceMonitor's labels on the Service's metadata.labels and give the Service port a `name:` that matches endpoints[].port. Verify with the Prometheus /targets page, not the manifest.

<a id="t03"></a>
## T03 — Namespace has workloads but no NetworkPolicy

**Default severity:** medium

Without any NetworkPolicy, every pod in the cluster can reach every pod in this namespace.

**Where it came from.** NetworkPolicies turned out to be the one runtime control that GitOps self-heal did not undo — and the namespaces without one were the ones exposed.

**Fix.** Add a default-deny ingress policy for the namespace, then allow the flows you actually need. (Only meaningful if your CNI enforces NetworkPolicy; flannel alone does not, k3s ships an enforcer.)

<a id="t04"></a>
## T04 — ConfigMap/Secret mounted with subPath never updates

**Default severity:** low

Files mounted via subPath are copied once at container start. Editing the ConfigMap or Secret changes nothing in the running pod — and GitOps will report the change as applied.

**Where it came from.** A homepage served from a subPath-mounted ConfigMap kept serving the old page after every 'successful' sync until someone restarted the deployment by hand.

**Fix.** Mount the whole volume (no subPath) if the app can re-read files, or add a checksum/config annotation to the pod template so a change triggers a rollout.

<a id="t05"></a>
## T05 — Two hostnames route to the same backend

**Default severity:** medium

When a retired app's route is left pointing at a port that another app now uses, the old hostname does not 404 — it serves the other app with HTTP 200, so health checks stay green.

**Where it came from.** A payment-webhook hostname and a workflow tool shared one NodePort in the tunnel config; the webhook URL happily returned the workflow tool's login page.

**Fix.** Decide per hostname whether it is still needed. Remove dead routes together with their DNS record. Prefer routing to a Service DNS name over a node IP + NodePort.

<a id="t06"></a>
## T06 — Replicas only *prefer* to spread

**Default severity:** medium

preferredDuringScheduling anti-affinity and ScheduleAnyway topology spread are hints. When nodes are tight the scheduler packs replicas onto the same node, and one node loss takes the whole service down.

**Where it came from.** 17 of 30 pods of a 'highly available' namespace ended up on one node; its anti-affinity was soft.

**Fix.** Use topologySpreadConstraints with whenUnsatisfiable: DoNotSchedule (or required anti-affinity) for services that must survive a node loss — and accept that they may go Pending when capacity is short.

<a id="t07"></a>
## T07 — Secret value written in plain text

**Default severity:** high

A password/token/key in container env `value:` or in a ConfigMap ends up in git, in `kubectl describe`, and in every backup — none of which are treated as secret stores.

**Where it came from.** Recurring finding during manifest reviews; the values are never shown in this tool's output.

**Fix.** Move the value into a Secret (ideally encrypted in git with SOPS or sealed-secrets) and reference it with valueFrom.secretKeyRef or envFrom.secretRef.
