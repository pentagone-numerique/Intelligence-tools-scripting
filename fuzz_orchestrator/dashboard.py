"""Dependency-free local dashboard for a completed or running campaign."""

from __future__ import annotations

import json
import mimetypes
import os
from collections import Counter, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit


_MAX_RESULT_ROWS = 1_000
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


_DASHBOARD_HTML = r'''<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fuzz Orchestrator Dashboard</title>
<style>
:root { color-scheme: dark; --bg:#0b1020; --panel:#121a2d; --panel2:#18233b; --line:#273653; --text:#e7edf8; --muted:#93a4c2; --good:#35d07f; --warn:#ffc857; --bad:#ff6b7a; --accent:#79a7ff; }
* { box-sizing:border-box; }
body { margin:0; background:linear-gradient(140deg,#0b1020 0%,#101a31 55%,#0b1020 100%); color:var(--text); font:14px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
main { max-width:1280px; margin:0 auto; padding:28px 22px 48px; }
header { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; margin-bottom:24px; }
h1 { margin:0 0 5px; font-size:clamp(23px,3vw,36px); letter-spacing:-.03em; }
h2 { margin:0 0 15px; font-size:17px; }
.subtitle,.muted { color:var(--muted); }
#live { color:var(--good); font-weight:700; }
.grid { display:grid; gap:15px; grid-template-columns:repeat(4,minmax(0,1fr)); margin-bottom:15px; }
.card,.panel { background:rgba(18,26,45,.9); border:1px solid var(--line); border-radius:15px; box-shadow:0 12px 35px rgba(0,0,0,.18); }
.card { padding:17px 18px; min-height:105px; }
.card .label { color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.12em; }
.card .value { margin-top:8px; font-size:29px; font-weight:750; letter-spacing:-.04em; }
.panel { padding:19px; margin-bottom:15px; }
.two { display:grid; grid-template-columns:1fr 1fr; gap:15px; }
.status-row { display:grid; grid-template-columns:145px 1fr 55px; gap:10px; align-items:center; margin:10px 0; }
.status-label { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.bar { height:10px; border-radius:99px; background:var(--panel2); overflow:hidden; }
.bar > i { display:block; height:100%; border-radius:99px; background:linear-gradient(90deg,var(--accent),#a68cff); }
pre { white-space:pre-wrap; overflow:auto; margin:0; padding:13px; border-radius:10px; background:#0a0f1c; color:#b7c8e7; max-height:300px; }
.table-wrap { overflow:auto; }
table { width:100%; border-collapse:collapse; min-width:690px; }
th,td { text-align:left; padding:10px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }
.status { display:inline-flex; border-radius:99px; padding:3px 9px; font-size:12px; font-weight:700; background:var(--panel2); }
.status.ok { color:var(--good); } .status.finding,.status.crash,.status.server_error,.status.nonzero_exit { color:var(--bad); }
.status.timeout { color:var(--warn); } .status.connection_error,.status.engine_error { color:#ff9b71; }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
.actions { display:flex; gap:9px; align-items:center; flex-wrap:wrap; }
button { border:1px solid var(--line); border-radius:9px; padding:8px 12px; color:var(--text); background:var(--panel2); cursor:pointer; }
button:hover { border-color:var(--accent); }
#timeline { width:100%; height:100px; display:block; background:#0a0f1c; border-radius:10px; }
.legend { display:flex; gap:15px; color:var(--muted); font-size:12px; margin-top:9px; flex-wrap:wrap; }
.legend span::before { content:""; display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:5px; background:var(--accent); }
.legend .bad::before { background:var(--bad); } .legend .warn::before { background:var(--warn); }
@media (max-width:850px) { .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .two { grid-template-columns:1fr; } header { display:block; } .actions { margin-top:15px; } }
@media (max-width:500px) { main { padding:20px 13px 35px; } .grid { grid-template-columns:1fr 1fr; gap:9px; } .card { padding:13px; } .card .value { font-size:24px; } }
</style>
</head>
<body>
<main>
<header>
  <div><h1>Fuzz Orchestrator</h1><div class="subtitle" id="run-name">Chargement de la campagne…</div></div>
  <div class="actions"><span id="live">● connexion</span><button id="refresh">Actualiser</button></div>
</header>
<section class="grid">
  <article class="card"><div class="label">Cas exécutés</div><div class="value" id="executed">—</div></article>
  <article class="card"><div class="label">Findings</div><div class="value" id="findings">—</div></article>
  <article class="card"><div class="label">Comportements nouveaux</div><div class="value" id="novel">—</div></article>
  <article class="card"><div class="label">Moteur / état</div><div class="value" id="engine" style="font-size:18px">—</div></article>
</section>
<section class="two">
  <article class="panel"><h2>Répartition des statuts</h2><div id="statuses"><span class="muted">Aucune donnée.</span></div></article>
  <article class="panel"><h2>Activité récente</h2><svg id="timeline" viewBox="0 0 900 100" preserveAspectRatio="none" role="img" aria-label="Activité récente"></svg><div class="legend"><span>OK</span><span class="bad">Finding</span><span class="warn">Timeout</span></div></article>
</section>
<section class="panel"><h2>Findings récents</h2><div class="table-wrap"><table><thead><tr><th>Cas</th><th>Statut</th><th>Taille</th><th>Durée</th><th>Liens</th></tr></thead><tbody id="findings-table"><tr><td colspan="5" class="muted">Aucun finding.</td></tr></tbody></table></div></section>
<section class="panel"><h2>Configuration</h2><details><summary>Afficher le manifeste</summary><pre id="manifest">Chargement…</pre></details></section>
</main>
<script>
const $ = id => document.getElementById(id);
const esc = value => String(value ?? "");
function statusClass(status) { return esc(status).replace(/[^a-zA-Z0-9_-]/g, "_"); }
function set(id, value) { $(id).textContent = value; }
function artifactLinks(row) {
  const links = row.artifact_urls || [];
  return links.map(item => { const a=document.createElement("a"); a.href=item.url; a.textContent=item.label; a.target="_blank"; a.rel="noopener"; return a; });
}
function renderStatuses(statuses, total) {
  const root=$("statuses"); root.replaceChildren();
  const entries=Object.entries(statuses || {}).sort((a,b)=>b[1]-a[1]);
  if (!entries.length) { root.innerHTML='<span class="muted">Aucune donnée.</span>'; return; }
  for (const [name,count] of entries) {
    const row=document.createElement("div"); row.className="status-row";
    const label=document.createElement("div"); label.className="status-label"; label.textContent=name;
    const bar=document.createElement("div"); bar.className="bar"; const fill=document.createElement("i"); fill.style.width=`${Math.min(100, total ? count/total*100 : 0)}%`; bar.append(fill);
    const value=document.createElement("div"); value.className="muted"; value.textContent=count;
    row.append(label,bar,value); root.append(row);
  }
}
function renderTimeline(rows) {
  const svg=$("timeline"); svg.replaceChildren();
  const recent=rows.slice(-80); const width=900, height=100, gap=width/Math.max(1,recent.length);
  recent.forEach((row,index)=>{ const rect=document.createElementNS("http://www.w3.org/2000/svg","rect"); rect.setAttribute("x",String(index*gap+1)); rect.setAttribute("y",row.status === "ok" ? "43" : (row.status === "timeout" ? "22" : "8")); rect.setAttribute("width",String(Math.max(2,gap-2))); rect.setAttribute("height",row.status === "ok" ? "49" : (row.status === "timeout" ? "70" : "84")); rect.setAttribute("rx","2"); rect.setAttribute("fill",row.status === "ok" ? "#79a7ff" : (row.status === "timeout" ? "#ffc857" : "#ff6b7a")); svg.append(rect); });
}
function renderFindings(rows) {
  const body=$("findings-table"); body.replaceChildren();
  const findings=rows.filter(row => row.status !== "ok").slice(-100).reverse();
  if (!findings.length) { const tr=document.createElement("tr"); tr.innerHTML='<td colspan="5" class="muted">Aucun finding.</td>'; body.append(tr); return; }
  for (const row of findings) {
    const tr=document.createElement("tr");
    const values=[row.case_id, row.status, `${row.input_size ?? 0} octets`, `${row.duration_ms ?? 0} ms`];
    values.forEach((value,index)=>{ const td=document.createElement("td"); if(index===1){const badge=document.createElement("span"); badge.className=`status ${statusClass(value)}`; badge.textContent=value; td.append(badge);} else td.textContent=value; tr.append(td); });
    const linksTd=document.createElement("td"); for(const link of artifactLinks(row)){ linksTd.append(link, document.createTextNode(" ")); } if(!linksTd.childNodes.length) linksTd.textContent="—"; tr.append(linksTd); body.append(tr);
  }
}
async function refresh() {
  try {
    const [summaryResponse, resultsResponse] = await Promise.all([fetch("/api/summary"), fetch("/api/results?limit=1000")]);
    if (!summaryResponse.ok || !resultsResponse.ok) throw new Error("HTTP");
    const overview=await summaryResponse.json(); const results=await resultsResponse.json();
    const summary=overview.summary || {}; const manifest=overview.manifest || {};
    set("run-name", `${manifest.config?.name || summary.engine_type || "campagne"} · ${overview.running ? "en cours" : "terminée"} · mise à jour ${overview.updated_at || "—"}`);
    set("executed", summary.executed ?? "0"); set("findings", summary.findings ?? "0"); set("novel", summary.novel_behaviors ?? "0"); set("engine", summary.engine_type || manifest.config?.engine?.type || "builtin");
    renderStatuses(summary.statuses || {}, summary.executed || 0); renderTimeline(results.results || []); renderFindings(results.results || []);
    $("manifest").textContent=JSON.stringify(manifest.config || manifest, null, 2);
    $("live").textContent=overview.running ? "● en cours" : "● terminée"; $("live").style.color=overview.running ? "var(--warn)" : "var(--good)";
  } catch (error) { $("live").textContent="● dashboard indisponible"; $("live").style.color="var(--bad)"; }
}
$("refresh").addEventListener("click", refresh); refresh(); setInterval(refresh, 5000);
</script>
</body>
</html>'''


def _json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _tail_results(run_dir: Path, limit: int, *, findings_only: bool = False) -> list[dict[str, Any]]:
    path = run_dir / "results.jsonl"
    if not path.is_file():
        return []
    rows: deque[dict[str, Any]] = deque(maxlen=limit)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for sequence, line in enumerate(handle, start=1):
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(value, dict):
                    continue
                if findings_only and value.get("status") == "ok":
                    continue
                value["sequence"] = sequence
                rows.append(value)
    except OSError:
        return []
    return list(rows)


def _summary(run_dir: Path) -> tuple[dict[str, Any], bool, str]:
    summary_path = run_dir / "summary.json"
    manifest = _json_file(run_dir / "manifest.json")
    summary = _json_file(summary_path)
    running = not summary_path.is_file()
    if not summary:
        rows = _tail_results(run_dir, _MAX_RESULT_ROWS)
        statuses = Counter(str(row.get("status", "unknown")) for row in rows)
        findings = sum(count for status, count in statuses.items() if status != "ok")
        summary = {
            "requested": 0,
            "executed": sum(statuses.values()),
            "findings": findings,
            "statuses": dict(statuses),
            "novel_behaviors": sum(
                1 for row in rows if row.get("metadata", {}).get("novel_behavior") is True
            ),
            "run_dir": str(run_dir),
        }
    updated = ""
    try:
        updated = __import__("datetime").datetime.fromtimestamp(
            max(path.stat().st_mtime for path in (run_dir / "results.jsonl", summary_path) if path.exists())
        ).astimezone().isoformat(timespec="seconds")
    except (OSError, ValueError):
        pass
    summary["run_dir"] = str(run_dir)
    if manifest.get("config", {}).get("engine", {}).get("type") and not summary.get("engine_type"):
        summary["engine_type"] = manifest["config"]["engine"]["type"]
    return {"summary": summary, "manifest": manifest}, running, updated


def _safe_path(run_dir: Path, relative: str) -> Path | None:
    if not relative or "\x00" in relative:
        return None
    root = run_dir.resolve()
    candidate = (root / unquote(relative)).resolve()
    try:
        if os.path.commonpath((str(root), str(candidate))) != str(root):
            return None
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _artifact_urls(run_dir: Path, row: dict[str, Any]) -> list[dict[str, str]]:
    paths: list[tuple[str, str]] = []
    artifact = row.get("metadata", {}).get("artifact")
    if isinstance(artifact, str):
        paths.append((artifact, "artifact"))
    case_id = row.get("case_id")
    if isinstance(case_id, str) and row.get("status") != "ok":
        stem = f"findings/case-{case_id}"
        paths.extend(((stem + suffix, label) for suffix, label in ((".bin", "input"), (".json", "metadata"), (".stdout", "stdout"), (".stderr", "stderr"))))
    result: list[dict[str, str]] = []
    for relative, label in paths:
        if _safe_path(run_dir, relative) is not None:
            result.append({"label": label, "url": "/artifact/" + relative.replace(os.sep, "/")})
    return result


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve one run directory; the instance is created with ``run_dir``."""

    server_version = "FuzzDashboard/0.2"

    @property
    def run_dir(self) -> Path:
        return self.server.run_dir  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self._send_bytes(_DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/summary":
            payload, running, updated = _summary(self.run_dir)
            payload["running"] = running
            payload["updated_at"] = updated
            self._send_json(payload)
            return
        if parsed.path == "/api/manifest":
            self._send_json(_json_file(self.run_dir / "manifest.json"))
            return
        if parsed.path == "/api/results":
            self._results(parsed.query)
            return
        if parsed.path.startswith("/artifact/"):
            self._artifact(parsed.path[len("/artifact/"):])
            return
        self._send_error_json(HTTPStatus.NOT_FOUND, "route not found")

    def _results(self, query: str) -> None:
        values = parse_qs(query)
        try:
            limit = max(1, min(_MAX_RESULT_ROWS, int(values.get("limit", ["250"])[0])))
        except ValueError:
            limit = 250
        status_filter = values.get("status", ["all"])[0]
        rows = _tail_results(self.run_dir, limit, findings_only=status_filter == "finding")
        if not rows:
            summary = _json_file(self.run_dir / "summary.json")
            artifacts = summary.get("artifacts", [])
            if isinstance(artifacts, list):
                rows = [
                    {"case_id": f"external-{index:08d}", "status": "finding", "input_size": 0, "metadata": {"artifact": item}}
                    for index, item in enumerate(artifacts, start=1) if isinstance(item, str)
                ][:limit]
        for row in rows:
            row["artifact_urls"] = _artifact_urls(self.run_dir, row)
        self._send_json({"results": rows, "count": len(rows)})

    def _artifact(self, relative: str) -> None:
        path = _safe_path(self.run_dir, relative)
        if path is None:
            self._send_error_json(HTTPStatus.NOT_FOUND, "artifact not found")
            return
        try:
            size = path.stat().st_size
            if size > _MAX_ARTIFACT_BYTES:
                self._send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "artifact is too large")
                return
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            with path.open("rb") as handle:
                while chunk := handle.read(64 * 1024):
                    self.wfile.write(chunk)
        except OSError:
            self._send_error_json(HTTPStatus.NOT_FOUND, "artifact unavailable")

    def _send_json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send_bytes(
            json.dumps(value, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
        )

    def _send_error_json(self, status: HTTPStatus, message: str) -> None:
        self._send_json({"error": message, "status": int(status)}, status)

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the dashboard usable from a terminal without logging every
        # five-second polling request.
        if self.path.startswith("/api/"):
            return
        super().log_message(format, *args)


def create_server(run_dir: str | Path, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    root = Path(run_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"run directory does not exist: {root}")

    def handler(*args: Any, **kwargs: Any) -> DashboardHandler:
        return DashboardHandler(*args, **kwargs)

    server = DashboardServer((host, port), handler)
    server.run_dir = root  # type: ignore[attr-defined]
    return server


def serve(run_dir: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    server = create_server(run_dir, host, port)
    print(f"Dashboard: http://{host}:{server.server_address[1]}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
