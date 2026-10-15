import os
import json
from dotenv import load_dotenv
from google import genai
from google.genai import types
import graph_tools

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=api_key)

# Expose our graph tools to the Gemini agent
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

def run_investigation(alert_description: str) -> str:
    print("\n" + "="*70)
    print(f"🚨 INCOMING AML ALERT: {alert_description}")
    print("="*70 + "\n")

    chat = client.chats.create(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(
            system_instruction=AGENT_SYSTEM_PROMPT,
            temperature=0.2,
            tools=available_tools
        )
    )

    prompt = f"Investigate this suspicious activity and take appropriate graph action:\n\n{alert_description}"
    response = chat.send_message(prompt)

    # Agent multi-turn tool calling loop
    step = 1
    while response.function_calls:
        for call in response.function_calls:
            tool_name = call.name
            tool_args = dict(call.args)
            print(f"🔍 [Agent Step {step}] Invoking Graph Tool: {tool_name}")
            print(f"   Args: {json.dumps(tool_args)}")

            # Execute the tool
            tool_func = getattr(graph_tools, tool_name)
            tool_result = tool_func(**tool_args)
            print(f"   ✓ Tool Output: {str(tool_result)[:180]}...")

            # Send result back to agent
            response = chat.send_message(
                types.Part.from_function_response(
                    name=tool_name,
                    response={"result": tool_result}
                )
            )
            step += 1

    print("\n" + "="*70)
    print("🛡️ INVESTIGATION COMPLETED - FINAL AUDIT DOSSIER:")
    print("="*70)
    print(response.text)
    return response.text

if __name__ == "__main__":
    alert = (
        "CRITICAL ANOMALY ALERT: Account ACC-100 (Acme Corp Payroll) experienced rapid unauthorized "
        "outbound fund dispersal totaling over $140,000 across multiple unfamiliar accounts within 15 minutes. "
        "Investigate the fund destination, detect if this is a coordinated money-laundering syndicate, "
        "uncover shared infrastructure or beneficial owners, and take quarantine action if warranted."
    )
    run_investigation(alert)
