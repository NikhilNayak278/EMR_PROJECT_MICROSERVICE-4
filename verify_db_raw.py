import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

DB_URL = os.getenv("DATABASE_URL")
print(f"Connecting to: {DB_URL}")

try:
    print("Attempting raw psycopg2 connection...")
    conn = psycopg2.connect(DB_URL, connect_timeout=10)
    print("SUCCESS: Connected to PostgreSQL!")
    conn.close()
except Exception as e:
    print(f"FAILURE: Raw connection failed: {e}")
