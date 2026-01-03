import requests
import json

DB_SERVICE_URL = "http://localhost:5004"

def test_search_endpoint():
    print("Testing search endpoint...")
    
    # Test without token (should work in DEV mode with my previous fix to token_required)
    try:
        resp = requests.get(
            f"{DB_SERVICE_URL}/api/fhir/search",
            params={"type": "Patient", "limit": 10},
            timeout=5
        )
        
        print(f"Response status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print("SUCCESS: Search endpoint returned 200 OK")
            print(f"Total resources: {data.get('total')}")
            print(f"Resources returned: {len(data.get('resources', []))}")
        elif resp.status_code == 401:
            print("FAILURE: Auth required (Dev mode check failed?)")
        else:
            print(f"FAILURE: Unexpected status code {resp.status_code}")
            print(f"Response: {resp.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_search_endpoint()
