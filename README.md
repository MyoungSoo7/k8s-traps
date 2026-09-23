# k8s-traps

Kubernetes manifest traps that **pass the linters and still break production**, packaged as a CLI and an MCP server so AI agents can check YAML before it ships.

<!-- mcp-name: io.github.MyoungSoo7/k8s-traps -->

Generic scanners (Kubescape, kube-linter, Trivy, Checkov) are good at baseline hygiene: resource limits, privileged containers, image tags. Use them. This project covers a different gap: configuration that is valid, lints clean, and fails **silently**. Each trap here comes from a real incident on a small production K3s cluster.

| ID | Trap | Default severity |
| --- | --- | --- |
| T01 | Service-link env vars (`<SVC>_PORT=tcp://…`) collide with the app's own settings | high |
| T02 | ServiceMonitor selects nothing (pod labels instead of Service labels, or an unnamed port) | high |
| T03 | Namespace has workloads but no NetworkPolicy | medium |
| T04 | ConfigMap/Secret mounted with `subPath` never updates | low |
| T05 | Two hostnames route to the same backend (a dead route serves another app with 200) | medium |
| T06 | Replicas only *prefer* to spread across nodes | medium |
| T07 | Secret value written in plain text (the value is never echoed back) | high |

Full explanations, including the incident behind each trap: [docs/traps.md](docs/traps.md).

## Scope and limits

- **Offline and read-only.** It parses the YAML you give it and never contacts a cluster.
- **Judged from the input only.** For example, T03 cannot see a NetworkPolicy that lives in another repo. Feed it a whole `helm template` render when you can.
- **Heuristics.** T01's same-name rule and T07's name patterns can raise false positives. Each finding says what it is based on.

## CLI

```bash
pip install git+https://github.com/MyoungSoo7/k8s-traps
helm template my-chart | k8s-traps            # stdin
k8s-traps manifests/ --fail-on medium         # files or directories; exit 1 at/above severity
k8s-traps deploy.yaml --json --trap T01 --trap T02
k8s-traps --list
```

## MCP server

The stdio server exposes three read-only tools:

- `audit_manifests(manifests: list[str], traps?: list[str])`
- `list_traps()`
- `explain_trap(trap_id)`

Claude Code:

```bash
claude mcp add k8s-traps -- k8s-traps-mcp
```

Generic MCP client config:

```json
{ "mcpServers": { "k8s-traps": { "command": "k8s-traps-mcp" } } }
```

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
.venv/bin/python scripts/gen_docs.py   # after editing the catalog in traps.py
```

Every trap has at least one test that must flag it and one that must stay clean. New traps are welcome; please describe the real failure each one comes from.

---

## 한국어 요약

린터는 통과하는데 운영에서 조용히 깨지는 쿠버네티스 매니페스트 함정을 잡는 CLI와 MCP 서버입니다. AI 에이전트가 YAML을 배포하기 전에 이 서버에 물어볼 수 있습니다.

- 함정 7개는 모두 실제 K3s 클러스터에서 겪은 장애에서 나왔습니다. 목록은 위 표에 있습니다.
- 리소스 한도나 권한 같은 기본 점검은 Kubescape나 kube-linter 몫입니다. 이 도구는 그 도구들과 같이 쓰도록 만들었습니다.
- 입력으로 받은 YAML만 오프라인으로 봅니다. 클러스터에는 접속하지 않습니다.
- 비밀값을 찾아도 그 값은 출력에 절대 싣지 않습니다.

## License

MIT
