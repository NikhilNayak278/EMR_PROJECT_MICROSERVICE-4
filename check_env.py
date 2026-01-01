import os
from dotenv import load_dotenv

# Explicitly load .env
load_dotenv()

print(f"DATABASE_URL: {os.getenv('DATABASE_URL')}")
print(f"FLASK_ENV: {os.getenv('FLASK_ENV')}")
