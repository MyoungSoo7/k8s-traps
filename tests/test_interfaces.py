import asyncio
import json

from k8s_traps import TRAPS, cli
from k8s_traps.server import mcp

BAD = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: prod}
spec:
  template:
    spec:
      containers:
      - {name: api, image: x, env: [{name: DB_PASSWORD, value: s3cret-value}]}
"""


def test_cli_json_and_exit_code(tmp_path, capsys):
    f = tmp_path / "d.yaml"
    f.write_text(BAD)
    assert cli.main([str(f), "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert {x["trap"] for x in out["findings"]} == {"T03", "T07"}
    assert "s3cret" not in json.dumps(out)


def test_cli_fail_on_never_and_list(tmp_path, capsys):
    f = tmp_path / "d.yaml"
    f.write_text(BAD)
    assert cli.main([str(f), "--fail-on", "never"]) == 0
    assert cli.main(["--list"]) == 0
    assert "T07" in capsys.readouterr().out


def test_mcp_tools_registered_and_callable():
    async def go():
        tools = {t.name for t in await mcp.list_tools()}
        assert tools == {"audit_manifests", "list_traps", "explain_trap"}
        result = await mcp.call_tool("audit_manifests", {"manifests": [BAD]})
        return result

    result = asyncio.run(go())
    assert "T07" in str(result) and "s3cret" not in str(result)


def test_every_trap_documented():
    import pathlib
    doc = (pathlib.Path(__file__).parent.parent / "docs" / "traps.md").read_text()
    for trap_id in TRAPS:
        assert f'<a id="{trap_id.lower()}"></a>' in doc
