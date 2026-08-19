"""Entity relationship graph — maps connections between discovered identities.

Generates:
- Mermaid diagram (Markdown-compatible)
- HTML interactive graph (vis-network.js)
- Summary statistics
"""
from collections import defaultdict


def build_entity_graph(findings: list[dict]) -> dict:
    """Build a graph of entities and their relationships.

    Returns:
        {
            "nodes": [{"id": str, "label": str, "type": str, "group": str}],
            "edges": [{"from": str, "to": str, "label": str}],
            "stats": {"total_nodes": int, "total_edges": int, "clusters": int}
        }
    """
    nodes = {}  # id -> node dict
    edges = []
    edge_set = set()

    # Extract primary target
    primary_target = None
    for f in findings:
        val = f.get("value", {})
        if isinstance(val, dict) and val.get("platform") and not primary_target:
            # First profile is likely the primary
            primary_target = val.get("username", val.get("platform"))
            break

    # Create nodes from findings
    for f in findings:
        data_type = f.get("data_type", "")
        source = f.get("source", "")
        value = f.get("value", {})
        confidence = f.get("confidence", 0.5)

        if data_type == "profile" and isinstance(value, dict):
            platform = value.get("platform", "unknown")
            username = value.get("username", value.get("title", ""))
            node_id = f"profile:{platform}:{username}"

            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": f"{platform}: {username}" if username else platform,
                    "type": "profile",
                    "group": platform,
                    "confidence": confidence,
                    "url": value.get("url", ""),
                }

        elif data_type == "email":
            email = value if isinstance(value, str) else value.get("email", "")
            if email:
                node_id = f"email:{email}"
                if node_id not in nodes:
                    nodes[node_id] = {
                        "id": node_id,
                        "label": email,
                        "type": "email",
                        "group": "email",
                        "confidence": confidence,
                    }

        elif data_type == "phone":
            phone = value if isinstance(value, str) else value.get("phone", "")
            if phone:
                node_id = f"phone:{phone}"
                if node_id not in nodes:
                    nodes[node_id] = {
                        "id": node_id,
                        "label": phone,
                        "type": "phone",
                        "group": "phone",
                        "confidence": confidence,
                    }

        elif data_type == "secret" and isinstance(value, dict):
            stype = value.get("type", "")
            svalue = value.get("value", "")[:20]
            if stype and svalue:
                node_id = f"secret:{stype}:{svalue}"
                if node_id not in nodes:
                    nodes[node_id] = {
                        "id": node_id,
                        "label": f"🔑 {stype}",
                        "type": "secret",
                        "group": "secret",
                        "confidence": confidence,
                    }

        elif data_type == "subdomain" and isinstance(value, dict):
            domain = value.get("domain", "")
            if domain:
                node_id = f"domain:{domain}"
                if node_id not in nodes:
                    nodes[node_id] = {
                        "id": node_id,
                        "label": domain,
                        "type": "domain",
                        "group": "domain",
                        "confidence": confidence,
                    }

        elif data_type == "breach" and isinstance(value, dict):
            breach_name = value.get("breach_name", value.get("source", ""))
            if breach_name:
                node_id = f"breach:{breach_name}"
                if node_id not in nodes:
                    nodes[node_id] = {
                        "id": node_id,
                        "label": f"⚠️ {breach_name}",
                        "type": "breach",
                        "group": "breach",
                        "confidence": confidence,
                    }

    # Build edges — connect entities that appear together
    # Group findings by source to find co-occurring entities
    source_entities = defaultdict(set)
    for f in findings:
        source = f.get("source", "")
        data_type = f.get("data_type", "")
        value = f.get("value", {})

        if data_type == "profile" and isinstance(value, dict):
            pid = f"profile:{value.get('platform', '')}:{value.get('username', value.get('title', ''))}"
            if pid in nodes:
                source_entities[source].add(pid)
        elif data_type == "email":
            email = value if isinstance(value, str) else value.get("email", "")
            eid = f"email:{email}"
            if eid in nodes:
                source_entities[source].add(eid)
        elif data_type == "phone":
            phone = value if isinstance(value, str) else value.get("phone", "")
            phid = f"phone:{phone}"
            if phid in nodes:
                source_entities[source].add(phid)

    # Create edges between entities found by same source
    for source, entities in source_entities.items():
        entity_list = list(entities)
        for i in range(len(entity_list)):
            for j in range(i + 1, len(entity_list)):
                edge_key = f"{entity_list[i]}|{entity_list[j]}"
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({
                        "from": entity_list[i],
                        "to": entity_list[j],
                        "label": source.split(":")[0][:15],
                    })

    # Connect emails/phones to profiles that reference them
    email_nodes = [n for n in nodes.values() if n["type"] == "email"]
    phone_nodes = [n for n in nodes.values() if n["type"] == "phone"]

    for f in findings:
        if f.get("data_type") == "profile" and isinstance(f.get("value"), dict):
            pid = f"profile:{f['value'].get('platform', '')}:{f['value'].get('username', f['value'].get('title', ''))}"
            if pid not in nodes:
                continue

            # Connect to emails
            for en in email_nodes:
                edge_key = f"{en['id']}|{pid}"
                reverse = f"{pid}|{en['id']}"
                if edge_key not in edge_set and reverse not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({"from": en["id"], "to": pid, "label": "linked"})

    # Calculate stats
    type_counts = defaultdict(int)
    for n in nodes.values():
        type_counts[n["type"]] += 1

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "by_type": dict(type_counts),
        },
    }


def generate_mermaid(graph: dict) -> str:
    """Generate Mermaid diagram syntax from the graph."""
    lines = ["graph LR"]

    # Style classes
    lines.append("    classDef profile fill:#1f6feb,stroke:#388bfd,color:#fff")
    lines.append("    classDef email fill:#238636,stroke:#2ea043,color:#fff")
    lines.append("    classDef phone fill:#a371f7,stroke:#8957e5,color:#fff")
    lines.append("    classDef secret fill:#da3633,stroke:#f85149,color:#fff")
    lines.append("    classDef breach fill:#d29922,stroke:#e3b341,color:#fff")
    lines.append("    classDef domain fill:#768390,stroke:#8b949e,color:#fff")
    lines.append("")

    # Nodes
    for node in graph["nodes"]:
        nid = node["id"].replace(":", "_").replace(".", "_").replace("@", "_").replace(" ", "_")[:40]
        label = node["label"].replace('"', "'")[:30]
        ntype = node.get("type", "profile")
        lines.append(f'    {nid}["{label}"]:::{ntype}')

    lines.append("")

    # Edges
    for edge in graph["edges"]:
        src = edge["from"].replace(":", "_").replace(".", "_").replace("@", "_").replace(" ", "_")[:40]
        dst = edge["to"].replace(":", "_").replace(".", "_").replace("@", "_").replace(" ", "_")[:40]
        lbl = edge.get("label", "").replace('"', "'")[:15]
        lines.append(f'    {src} -->|"{lbl}"| {dst}')

    return "\n".join(lines)


def generate_html_graph(graph: dict) -> str:
    """Generate HTML with vis-network.js interactive graph."""
    import json

    nodes_json = json.dumps([{
        "id": n["id"],
        "label": n["label"],
        "group": n.get("group", "default"),
        "title": f"{n['type']}: {n['label']} (conf: {n.get('confidence', 0):.0%})",
        "shape": _node_shape(n["type"]),
    } for n in graph["nodes"]], ensure_ascii=False)

    edges_json = json.dumps([{
        "from": e["from"],
        "to": e["to"],
        "label": e.get("label", ""),
        "arrows": "to",
        "color": {"color": "#30363d", "highlight": "#58a6ff"},
    } for e in graph["edges"]], ensure_ascii=False)

    return f"""<div id="entity-graph" style="height:500px;background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:16px;"></div>
<script src="https://unpkg.com/vis-network@9/standalone/umd/vis-network.min.js"></script>
<script>
(function() {{
    var nodes = new vis.DataSet({nodes_json});
    var edges = new vis.DataSet({edges_json});
    var container = document.getElementById('entity-graph');
    var data = {{ nodes: nodes, edges: edges }};
    var options = {{
        groups: {{
            profile: {{ color: {{ background: '#1f6feb', border: '#388bfd' }}, font: {{ color: '#fff' }} }},
            email: {{ color: {{ background: '#238636', border: '#2ea043' }}, font: {{ color: '#fff' }} }},
            phone: {{ color: {{ background: '#a371f7', border: '#8957e5' }}, font: {{ color: '#fff' }} }},
            secret: {{ color: {{ background: '#da3633', border: '#f85149' }}, font: {{ color: '#fff' }} }},
            breach: {{ color: {{ background: '#d29922', border: '#e3b341' }}, font: {{ color: '#fff' }} }},
            domain: {{ color: {{ background: '#768390', border: '#8b949e' }}, font: {{ color: '#fff' }} }},
        }},
        physics: {{ solver: 'forceAtlas2Based', stabilization: {{ iterations: 100 }} }},
        edges: {{ font: {{ color: '#8b949e', size: 10 }}, smooth: {{ type: 'continuous' }} }},
        interaction: {{ hover: true, tooltipDelay: 100 }},
    }};
    var network = new vis.Network(container, data, options);
}})();
</script>"""


def _node_shape(node_type: str) -> str:
    """Map node type to vis-network shape."""
    shapes = {
        "profile": "dot",
        "email": "diamond",
        "phone": "square",
        "secret": "star",
        "triangle": "triangle",
        "domain": "hexagon",
        "breach": "triangleDown",
    }
    return shapes.get(node_type, "dot")
