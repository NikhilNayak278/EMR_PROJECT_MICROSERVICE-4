from sqlalchemy import create_engine
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')

try:
    engine = create_engine(DATABASE_URL)
    connection = engine.connect()
    print("✅ Database connection successful!")
    connection.close()
except Exception as e:
    print(f"❌ Database connection failed: {str(e)}")
