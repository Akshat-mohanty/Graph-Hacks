import os
import json
from typing import Dict, Any, List
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from falkordb import FalkorDB
from google import genai
from google.genai import types

import graph_tools
import seed_data

load_dotenv()

app = FastAPI(title="SentinelGraph - Autonomous Financial Crime Hunter")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

host = os.getenv("FALKORDB_HOST")
port = int(os.getenv("FALKORDB_PORT", 53262))
password = os.getenv("FALKORDB_PASSWORD")
username = os.getenv("FALKORDB_USERNAME", "falkordb")

db = FalkorDB(
    host=host,
    port=port,
    username=username,
    password=password,
    ssl=False,
    socket_timeout=10,
)
graph = db.select_graph("sentinel_fraud_db")

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

available_tools = [
    graph_tools.trace_fund_flow,
    graph_tools.detect_cycles,
    graph_tools.find_shared_infrastructure,
    graph_tools.compute_node_risk_centrality,
    graph_tools.freeze_and_quarantine_syndicate
]

AGENT_SYSTEM_PROMPT = """
You are SentinelGraph, an autonomous AI financial crime and fraud-investigation agent operating over FalkorDB.
You are participating in Track 01 ("Agents That Act on Connected Data").

Your goal is to investigate suspicious accounts and transactions by navigating the connected knowledge graph.
RULES:
1. NEVER guess or assume relationships: always use your graph tools to traverse edges and verify connections.
2. When investigating a suspicious account, trace its multi-hop fund flows (1 to 4 hops) to find intermediate mules and ultimate sinks/aggregators.
3. Check for circular kickbacks (cycles) using detect_cycles.
4. Check for shared hardware/Tor devices or hidden beneficial owners using find_shared_infrastructure.
5. If a coordinated syndicate or money laundering ring is confirmed, use freeze_and_quarantine_syndicate to isolate the malicious accounts.
6. Always deliver an EXPLAINABLE AUDIT DOSSIER showing:
   - The exact multi-hop graph path (e.g., A -[TX]-> B -[TX]-> C).
   - Shared infrastructure evidence (e.g., common Tor IP or Device ID).
   - Real-world action taken (e.g., accounts frozen in FalkorDB with timestamp).
"""

@app.get("/api/graph")
def get_graph_data():
    nodes_q = "MATCH (n) RETURN id(n) AS internal_id, labels(n)[0] AS label, properties(n) AS props"
    edges_q = "MATCH (s)-[r]->(t) RETURN id(s) AS source, id(t) AS target, type(r) AS type, properties(r) AS props"
    
    n_res = graph.query(nodes_q)
    e_res = graph.query(edges_q)
    
    nodes = []
    for row in n_res.result_set:
        props = row[2]
        label_type = row[1]
        node_id = props.get("id", str(row[0]))
        title_text = f"{label_type}: {node_id}\n" + "\n".join([f"{k}: {v}" for k, v in props.items()])
        
        color = "#6366f1"
        if label_type == "Account":
            status = props.get("status", "ACTIVE")
            color = "#ef4444" if status == "FROZEN" else "#3b82f6"
        elif label_type == "Person":
            color = "#f59e0b"
        elif label_type == "Company":
            color = "#10b981"
        elif label_type == "Device":
            color = "#8b5cf6"
            
        nodes.append({
            "id": row[0],
            "label": f"{label_type}\n{node_id}",
            "title": title_text,
            "group": label_type,
            "color": color,
            "raw_id": node_id,
            "status": props.get("status", "ACTIVE")
        })
        
    edges = []
    for row in e_res.result_set:
        rel_type = row[2]
        props = row[3]
        label = rel_type
        if "amount" in props:
            label += f"\n${props['amount']:,.0f}"
        edges.append({
            "from": row[0],
            "to": row[1],
            "label": label,
            "arrows": "to",
            "font": {"size": 10, "align": "middle"}
        })
        
    return {"nodes": nodes, "edges": edges}

@app.post("/api/reseed")
def reseed():
    seed_data.seed_database()
    return {"status": "SUCCESS", "message": "FalkorDB Graph Reset & Reseeded with Syndicate Scenario"}

@app.post("/api/investigate")
def investigate(payload: Dict[str, str]):
    alert_text = payload.get("alert", (
        "CRITICAL ANOMALY ALERT: Account ACC-100 (Acme Corp Payroll) experienced rapid unauthorized "
        "outbound fund dispersal totaling over $140,000 across multiple unfamiliar accounts within 15 minutes. "
        "Investigate the fund destination, detect if this is a coordinated money-laundering syndicate, "
        "uncover shared infrastructure or beneficial owners, and take quarantine action if warranted."
    ))

    chat = client.chats.create(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(
            system_instruction=AGENT_SYSTEM_PROMPT,
            temperature=0.2,
            tools=available_tools
        )
    )

    steps = []
    prompt = f"Investigate this suspicious activity and take appropriate graph action:\n\n{alert_text}"
    response = chat.send_message(prompt)

    while response.function_calls:
        for call in response.function_calls:
            t_name = call.name
            t_args = dict(call.args)
            tool_func = getattr(graph_tools, t_name)
            t_result = tool_func(**t_args)
            
            steps.append({
                "tool": t_name,
                "args": t_args,
                "result": t_result
            })
            
            response = chat.send_message(
                types.Part.from_function_response(
                    name=t_name,
                    response={"result": t_result}
                )
            )

    return {
        "steps": steps,
        "dossier": response.text
    }

@app.get("/", response_class=HTMLResponse)
def index():
    with open("index.html", "r") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
