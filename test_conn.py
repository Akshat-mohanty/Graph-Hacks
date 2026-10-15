import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

host = os.getenv("FALKORDB_HOST")
port = int(os.getenv("FALKORDB_PORT", 53262))
password = os.getenv("FALKORDB_PASSWORD")
username = os.getenv("FALKORDB_USERNAME", "falkordb")

print(f"Connecting to {host}:{port} with user '{username}'...")
try:
    db = FalkorDB(
        host=host,
        port=port,
        username=username,
        password=password,
        ssl=False,
        socket_timeout=5,
    )
    g = db.select_graph("sentinel_fraud_db")
    res = g.query("RETURN 'FalkorDB Connected Successfully' AS status")
    print("SUCCESS:", res.result_set)
except Exception as e:
    print("FAILED:", e)
