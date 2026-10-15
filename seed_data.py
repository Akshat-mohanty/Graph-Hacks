import os
import time
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

host = os.getenv("FALKORDB_HOST")
port = int(os.getenv("FALKORDB_PORT", 53262))
password = os.getenv("FALKORDB_PASSWORD")
username = os.getenv("FALKORDB_USERNAME", "falkordb")

print(f"Connecting to FalkorDB Cloud ({host}:{port})...")
db = FalkorDB(
    host=host,
    port=port,
    username=username,
    password=password,
    ssl=False,
    socket_timeout=10,
)
graph = db.select_graph("sentinel_fraud_db")

def seed_database():
    print("Clearing any existing graph data...")
    try:
        graph.query("MATCH (n) DETACH DELETE n")
    except Exception as e:
        print("Note on cleanup:", e)

    print("Creating indices for high-speed multi-hop traversals...")
    try:
        graph.query("CREATE INDEX FOR (a:Account) ON (a.id)")
        graph.query("CREATE INDEX FOR (p:Person) ON (p.id)")
        graph.query("CREATE INDEX FOR (d:Device) ON (d.id)")
    except Exception as e:
        print("Index creation note:", e)

    print("Ingesting Entities: Accounts, People, Shell Companies, and Devices...")

    accounts_cypher = """
    CREATE 
      (acc_victim:Account {id: 'ACC-100', owner: 'Acme Corp Payroll', balance: 250000.0, risk_score: 0.1, status: 'ACTIVE'}),
      (acc_mule1:Account {id: 'ACC-201', owner: 'Dave Miller', balance: 4800.0, risk_score: 0.65, status: 'ACTIVE'}),
      (acc_mule2:Account {id: 'ACC-202', owner: 'Elena Rostova', balance: 4950.0, risk_score: 0.70, status: 'ACTIVE'}),
      (acc_mule3:Account {id: 'ACC-203', owner: 'Liam Chen', balance: 4900.0, risk_score: 0.60, status: 'ACTIVE'}),
      (acc_shell:Account {id: 'ACC-300', owner: 'Apex Global Logistics LLC', balance: 14500.0, risk_score: 0.85, status: 'ACTIVE'}),
      (acc_kingpin:Account {id: 'ACC-999', owner: 'Viktor Vance Offshore', balance: 950000.0, risk_score: 0.95, status: 'ACTIVE'}),
      
      (acc_legit1:Account {id: 'ACC-801', owner: 'Sarah Connor', balance: 3200.0, risk_score: 0.05, status: 'ACTIVE'}),
      (acc_legit2:Account {id: 'ACC-802', owner: 'John Connor', balance: 1500.0, risk_score: 0.05, status: 'ACTIVE'})
    """
    graph.query(accounts_cypher)

    entities_cypher = """
    CREATE
      (p_viktor:Person {id: 'P-99', name: 'Viktor Vance', jurisdiction: 'Panama', flagged_pep: true}),
      (p_dave:Person {id: 'P-21', name: 'Dave Miller', jurisdiction: 'UK', flagged_pep: false}),
      (p_elena:Person {id: 'P-22', name: 'Elena Rostova', jurisdiction: 'Cyprus', flagged_pep: false}),
      (c_apex:Company {id: 'C-30', name: 'Apex Global Logistics LLC', reg_number: 'SHELL-78912', jurisdiction: 'BVI'}),
      (c_acme:Company {id: 'C-10', name: 'Acme Corp', reg_number: 'CORP-10001', jurisdiction: 'US'})
    """
    graph.query(entities_cypher)

    devices_cypher = """
    CREATE
      (dev_syndicate:Device {id: 'DEV-DARK-01', ip: '194.26.29.112', mac_hash: '9f:4a:1b:88:cc:01', user_agent: 'TorBrowser/12.5'}),
      (dev_clean1:Device {id: 'DEV-CLEAN-01', ip: '72.14.201.5', mac_hash: '11:22:33:44:55:66', user_agent: 'Safari/MacIntel'}),
      (dev_clean2:Device {id: 'DEV-CLEAN-02', ip: '142.250.190.46', mac_hash: 'aa:bb:cc:dd:ee:ff', user_agent: 'Chrome/Win10'})
    """
    graph.query(devices_cypher)

    print("Wiring Relationships & Transactions (Multi-Hop Graph Connections)...")

    relations_cypher = """
    MATCH (acc_victim:Account {id: 'ACC-100'}), (c_acme:Company {id: 'C-10'}),
          (acc_mule1:Account {id: 'ACC-201'}), (p_dave:Person {id: 'P-21'}),
          (acc_mule2:Account {id: 'ACC-202'}), (p_elena:Person {id: 'P-22'}),
          (acc_shell:Account {id: 'ACC-300'}), (c_apex:Company {id: 'C-30'}),
          (acc_kingpin:Account {id: 'ACC-999'}), (p_viktor:Person {id: 'P-99'}),
          (dev_syndicate:Device {id: 'DEV-DARK-01'}),
          (dev_clean1:Device {id: 'DEV-CLEAN-01'})
    CREATE
      (c_acme)-[:OWNS_ACCOUNT]->(acc_victim),
      (p_dave)-[:OWNS_ACCOUNT]->(acc_mule1),
      (p_elena)-[:OWNS_ACCOUNT]->(acc_mule2),
      (c_apex)-[:OWNS_ACCOUNT]->(acc_shell),
      (p_viktor)-[:BENEFICIAL_OWNER {shares: 100}]->(c_apex),
      (p_viktor)-[:OWNS_ACCOUNT]->(acc_kingpin),

      (acc_mule1)-[:ACCESSED_VIA {last_login: '2026-10-14 02:15:00'}]->(dev_syndicate),
      (acc_mule2)-[:ACCESSED_VIA {last_login: '2026-10-14 02:22:00'}]->(dev_syndicate),
      (acc_kingpin)-[:ACCESSED_VIA {last_login: '2026-10-14 03:00:00'}]->(dev_syndicate),

      (acc_victim)-[:ACCESSED_VIA {last_login: '2026-10-14 09:00:00'}]->(dev_clean1)
    """
    graph.query(relations_cypher)

    tx_cypher = """
    MATCH (v:Account {id: 'ACC-100'}),
          (m1:Account {id: 'ACC-201'}),
          (m2:Account {id: 'ACC-202'}),
          (m3:Account {id: 'ACC-203'}),
          (shell:Account {id: 'ACC-300'}),
          (kingpin:Account {id: 'ACC-999'}),
          (l1:Account {id: 'ACC-801'}),
          (l2:Account {id: 'ACC-802'})
    CREATE
      (v)-[:TRANSFERRED {tx_id: 'TX-101', amount: 50000.0, timestamp: '2026-10-15 01:00:00'}]->(m1),
      (v)-[:TRANSFERRED {tx_id: 'TX-102', amount: 48000.0, timestamp: '2026-10-15 01:05:00'}]->(m2),
      (v)-[:TRANSFERRED {tx_id: 'TX-103', amount: 45000.0, timestamp: '2026-10-15 01:10:00'}]->(m3),

      (m1)-[:TRANSFERRED {tx_id: 'TX-201', amount: 47000.0, timestamp: '2026-10-15 02:00:00'}]->(shell),
      (m2)-[:TRANSFERRED {tx_id: 'TX-202', amount: 46000.0, timestamp: '2026-10-15 02:15:00'}]->(shell),
      (m3)-[:TRANSFERRED {tx_id: 'TX-203', amount: 44000.0, timestamp: '2026-10-15 02:30:00'}]->(shell),

      (shell)-[:TRANSFERRED {tx_id: 'TX-301', amount: 135000.0, timestamp: '2026-10-15 03:00:00'}]->(kingpin),

      (kingpin)-[:TRANSFERRED {tx_id: 'TX-401', amount: 15000.0, timestamp: '2026-10-15 03:30:00'}]->(m1),

      (l1)-[:TRANSFERRED {tx_id: 'TX-901', amount: 120.0, timestamp: '2026-10-15 04:00:00'}]->(l2)
    """
    graph.query(tx_cypher)

    node_count = graph.query("MATCH (n) RETURN count(n) AS total_nodes").result_set[0][0]
    edge_count = graph.query("MATCH ()-[r]->() RETURN count(r) AS total_edges").result_set[0][0]
    print(f"\n Graph Ingestion COMPLETE!")
    print(f"Total Nodes: {node_count}")
    print(f"Total Edges: {edge_count}")

if __name__ == "__main__":
    seed_database()
