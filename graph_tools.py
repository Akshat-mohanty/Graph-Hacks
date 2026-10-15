import os
from typing import Dict, Any, List
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

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

def trace_fund_flow(start_account_id: str, max_depth: int = 4) -> Dict[str, Any]:
    query = f"""
    MATCH path = (start:Account {{id: '{start_account_id}'}})-[t:TRANSFERRED*1..{max_depth}]->(dest:Account)
    RETURN [n in nodes(path) | {{id: n.id, owner: n.owner, status: n.status}}] AS path_nodes,
           [r in relationships(path) | {{tx_id: r.tx_id, amount: r.amount, timestamp: r.timestamp}}] AS transfers,
           length(path) AS hops
    ORDER BY hops ASC
    """
    res = graph.query(query)
    paths = []
    for row in res.result_set:
        paths.append({
            "hops": row[2],
            "nodes": row[0],
            "transfers": row[1]
        })
    return {"start_account": start_account_id, "discovered_paths_count": len(paths), "paths": paths}

def detect_cycles(start_account_id: str, max_depth: int = 5) -> Dict[str, Any]:
    query = f"""
    MATCH path = (a:Account {{id: '{start_account_id}'}})-[:TRANSFERRED*2..{max_depth}]->(a)
    RETURN [n in nodes(path) | n.id] AS cycle_account_ids,
           [r in relationships(path) | {{tx_id: r.tx_id, amount: r.amount}}] AS cycle_transfers,
           length(path) AS loop_length
    """
    res = graph.query(query)
    cycles = []
    for row in res.result_set:
        cycles.append({
            "loop_length": row[2],
            "cycle_accounts": row[0],
            "transfers": row[1]
        })
    return {"detected_cycles": cycles, "has_circular_flow": len(cycles) > 0}

def find_shared_infrastructure(account_ids: List[str]) -> Dict[str, Any]:
    acc_filter = ", ".join([f"'{acc}'" for acc in account_ids])
    query = f"""
    MATCH (a:Account)-[:ACCESSED_VIA]->(d:Device)<-[:ACCESSED_VIA]-(b:Account)
    WHERE a.id IN [{acc_filter}] AND a.id <> b.id
    RETURN a.id AS account_1, b.id AS account_2, d.id AS device_id, d.ip AS ip, d.user_agent AS user_agent
    """
    res = graph.query(query)
    shared_devices = []
    for row in res.result_set:
        shared_devices.append({
            "account_1": row[0],
            "account_2": row[1],
            "shared_device": row[2],
            "ip": row[3],
            "user_agent": row[4]
        })

    bo_query = f"""
    MATCH (a:Account)<-[:OWNS_ACCOUNT]-(c:Company)<-[:BENEFICIAL_OWNER]-(p:Person)-[:OWNS_ACCOUNT]->(b:Account)
    WHERE (a.id IN [{acc_filter}] OR b.id IN [{acc_filter}]) AND a.id <> b.id
    RETURN a.id AS account_shell, c.name AS company, p.name AS ultimate_owner, b.id AS owner_personal_account
    """
    bo_res = graph.query(bo_query)
    beneficial_links = []
    for row in bo_res.result_set:
        beneficial_links.append({
            "shell_account": row[0],
            "company": row[1],
            "ultimate_beneficial_owner": row[2],
            "owner_account": row[3]
        })

    return {
        "shared_device_clusters": shared_devices,
        "beneficial_owner_links": beneficial_links
    }

def compute_node_risk_centrality(account_id: str) -> Dict[str, Any]:
    query = f"""
    MATCH (a:Account {{id: '{account_id}'}})
    OPTIONAL MATCH (in_acc:Account)-[r_in:TRANSFERRED]->(a)
    OPTIONAL MATCH (a)-[r_out:TRANSFERRED]->(out_acc:Account)
    RETURN a.id AS id,
           a.owner AS owner,
           a.balance AS balance,
           count(DISTINCT in_acc) AS in_degree,
           count(DISTINCT out_acc) AS out_degree,
           coalesce(sum(r_in.amount), 0) AS total_inflow,
           coalesce(sum(r_out.amount), 0) AS total_outflow
    """
    res = graph.query(query)
    if not res.result_set:
        return {"error": f"Account {account_id} not found"}
    row = res.result_set[0]
    inflow = float(row[5])
    outflow = float(row[6])
    is_mule = (row[3] >= 1 and row[4] >= 1 and abs(inflow - outflow) < (0.2 * max(inflow, outflow, 1.0)))
    return {
        "account_id": row[0],
        "owner": row[1],
        "balance": row[2],
        "in_degree": row[3],
        "out_degree": row[4],
        "total_inflow": inflow,
        "total_outflow": outflow,
        "is_passthrough_mule_candidate": is_mule
    }

def freeze_and_quarantine_syndicate(account_ids: List[str], reason: str) -> Dict[str, Any]:
    acc_filter = ", ".join([f"'{acc}'" for acc in account_ids])
    query = f"""
    MATCH (a:Account)
    WHERE a.id IN [{acc_filter}]
    SET a.status = 'FROZEN', 
        a.freeze_reason = '{reason}',
        a.quarantined_at = timestamp()
    RETURN a.id AS frozen_id, a.owner AS owner, a.status AS status
    """
    res = graph.query(query)
    frozen = [{"id": r[0], "owner": r[1], "status": r[2]} for r in res.result_set]
    return {
        "action": "FREEZE_AND_QUARANTINE",
        "reason": reason,
        "affected_accounts": frozen,
        "count": len(frozen)
    }

if __name__ == "__main__":
    print("Testing trace_fund_flow from ACC-100 (Victim)...")
    print(trace_fund_flow("ACC-100", max_depth=3))
    
    print("\nTesting detect_cycles on ACC-201 (Mule 1)...")
    print(detect_cycles("ACC-201"))
    
    print("\nTesting find_shared_infrastructure across mules and kingpin...")
    print(find_shared_infrastructure(["ACC-201", "ACC-202", "ACC-999"]))
