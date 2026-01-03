import requests
import json

DB_SERVICE_URL = "http://localhost:5004"

def test_search_with_valid_token():
    print("Testing search endpoint with VALID token...")
    
    # 1. Register/Login to get token
    session = requests.Session()
    
    # Register dummy user
    import time
    username = f"admin_{int(time.time())}"
    try:
        reg_resp = session.post(f"{DB_SERVICE_URL}/api/auth/register", json={
            "username": username,
            "password": "password123",
            "email": f"{username}@example.com",
            "role": "ADMIN" 
        })
    except:
        pass 

    # Login
    auth_resp = session.post(f"{DB_SERVICE_URL}/api/auth/login", json={
        "username": username,
        "password": "password123"
    })
    
    if auth_resp.status_code != 200:
        print(f"Login failed: {auth_resp.text}")
        return

    token = auth_resp.json()['access_token']
    print(f"Got token: {token[:10]}...")

    # 2. Test search with token
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    try:
        resp = requests.get(
            f"{DB_SERVICE_URL}/api/fhir/search",
            params={"type": "Patient", "limit": "abc"},
            headers=headers,
            timeout=5
        )
        
        print(f"Response status: {resp.status_code}")
        print(f"Response body: {resp.text}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_search_with_valid_token()
