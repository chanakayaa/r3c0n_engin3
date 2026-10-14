"""
Asset-relationship graph builder and renderer.

Produces a read-only map of how assets relate (subdomain -> ip -> service,
host -> technology). This is the foundation for the tender's section-4
"attack-path visualisation" - it shows reachability/structure, not exploitation.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict

from .store import Store

# Pinned CDN (>2 weeks old) for the interactive renderer; the JSON builder
# itself has no external dependency and works fully offline.
_CYTOSCAPE = "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"

_KIND_COLOR = {
    "subdomain": "#38bdf8",
    "ip": "#a78bfa",
    "service": "#f472b6",
    "url": "#34d399",
    "technology": "#fbbf24",
}


def build_graph(store: Store, target: str) -> Dict[str, Any]:
    """Return {nodes, edges} for a target (thin wrapper over Store.graph)."""
    return store.graph(target)


def graph_html(data: Dict[str, Any], target: str) -> str:
    """Render a self-contained interactive graph page (cytoscape via CDN)."""
    elements = []
    for n in data.get("nodes", []):
        risk = n.get("risk", 0) or 0
        elements.append({"data": {
            "id": f"n{n['id']}", "label": n["key"], "kind": n["kind"],
            "risk": risk, "color": _KIND_COLOR.get(n["kind"], "#94a3b8"),
        }})
    for e in data.get("edges", []):
        elements.append({"data": {
            "source": f"n{e['source']}", "target": f"n{e['target']}",
            "label": e.get("rel", ""),
        }})
    elements_json = json.dumps(elements)
    legend = " ".join(
        f'<span style="color:{c}">●</span> {html.escape(k)}'
        for k, c in _KIND_COLOR.items())

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Asset graph - {html.escape(target)}</title>
<style>
  html,body{{margin:0;height:100%;background:#0f172a;color:#e5e7eb;
    font-family:-apple-system,Segoe UI,Arial,sans-serif}}
  #bar{{padding:10px 16px;border-bottom:1px solid #1e293b}}
  #bar h1{{margin:0;font-size:16px;color:#38bdf8}}
  #legend{{font-size:12px;color:#94a3b8;margin-top:4px}}
  #cy{{width:100%;height:calc(100% - 58px)}}
</style>
<script src="{_CYTOSCAPE}"></script>
</head><body>
<div id="bar"><h1>Asset relationship map &mdash; {html.escape(target)}</h1>
<div id="legend">{legend} &nbsp;|&nbsp; node size &amp; red ring = higher risk</div></div>
<div id="cy"></div>
<script>
const elements = {elements_json};
const cy = cytoscape({{
  container: document.getElementById('cy'),
  elements: elements,
  style: [
    {{selector:'node', style:{{
      'background-color':'data(color)','label':'data(label)','color':'#e5e7eb',
      'font-size':9,'width':'mapData(risk,0,100,14,46)',
      'height':'mapData(risk,0,100,14,46)',
      'border-width':'mapData(risk,0,100,0,4)','border-color':'#ef4444'}}}},
    {{selector:'edge', style:{{
      'width':1,'line-color':'#334155','target-arrow-color':'#334155',
      'target-arrow-shape':'triangle','curve-style':'bezier',
      'label':'data(label)','font-size':7,'color':'#64748b'}}}}
  ],
  layout: {{name:'cose', animate:false, padding:30}}
}});
</script>
</body></html>"""
