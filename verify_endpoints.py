
import requests
import time
import subprocess
import sys
import os
import signal
import json
import socket

# Configuration
BASE_URL = "http://localhost:5000/api"
AUTH_URL = f"{BASE_URL}/auth"
FHIR_URL = f"{BASE_URL}/fhir"
ADMIN_URL = f"{BASE_URL}/admin"

class TextColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_success(msg):
    print(f"{TextColors.OKGREEN}[PASS] {msg}{TextColors.ENDC}")

def log_fail(msg, error=None):
    print(f"{TextColors.FAIL}[FAIL] {msg}{TextColors.ENDC}")
    if error:
        print(f"{TextColors.FAIL}Error: {error}{TextColors.ENDC}")

def log_section(msg):
    print(f"\n{TextColors.HEADER}{TextColors.BOLD}=== {msg} ==={TextColors.ENDC}")

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def start_server():
    if is_port_in_use(5000):
        print(f"{TextColors.WARNING}Port 5000 is already in use. Assuming server is running.{TextColors.ENDC}")
        return None

    print("Starting Flask server...")
    # Using python directly to match system python
    process = subprocess.Popen([sys.executable, "app.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=os.getcwd())
    
    # Wait for health check
    for i in range(10):
        try:
            resp = requests.get(f"{BASE_URL}/health")
            if resp.status_code == 200:
                print(f"{TextColors.OKGREEN}Server started successfully.{TextColors.ENDC}")
                return process
        except:
            pass
        time.sleep(2)
        print(f"Waiting for server... ({i+1}/10)")
    
    print(f"{TextColors.FAIL}Failed to start server.{TextColors.ENDC}")
    stop_server(process)
    sys.exit(1)

def stop_server(process):
    if process:
        print("\nStopping Flask server...")
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            process.kill()

# Store tokens
tokens = {}

def run_tests():
    # 1. AUTH TESTS
    log_section("AUTHENTICATION TESTS")
    
    # Login Admin
    try:
        resp = requests.post(f"{AUTH_URL}/login", json={"username": "admin", "password": "admin123"})
        if resp.status_code == 200:
            tokens['ADMIN'] = resp.json()['access_token']
            log_success("Login Admin")
        else:
            log_fail("Login Admin", resp.text)
    except Exception as e:
        log_fail("Login Admin Exception", str(e))

    # Login Doctor
    try:
        resp = requests.post(f"{AUTH_URL}/login", json={"username": "doctor1", "password": "doctor123"})
        if resp.status_code == 200:
            tokens['DOCTOR'] = resp.json()['access_token']
            log_success("Login Doctor")
        else:
            log_fail("Login Doctor", resp.text)
    except Exception as e:
        log_fail("Login Doctor Exception", str(e))

    # 2. FHIR TESTS
    log_section("FHIR TESTS")
    
    if 'ADMIN' not in tokens or 'DOCTOR' not in tokens:
        print("Skipping FHIR tests due to missing tokens")
        return

    admin_headers = {"Authorization": f"Bearer {tokens['ADMIN']}"}
    doctor_headers = {"Authorization": f"Bearer {tokens['DOCTOR']}"}
    
    # Get Patient (Admin should see all)
    try:
        resp = requests.get(f"{FHIR_URL}/Patient/pat-001", headers=admin_headers)
        if resp.status_code == 200:
            log_success("Get Patient (Admin)")
        else:
            log_fail("Get Patient (Admin)", resp.text)
    except Exception as e:
        log_fail("Get Patient", str(e))
        
    # Get Patient Complete Bundle
    try:
        resp = requests.get(f"{FHIR_URL}/patient/pat-001/complete", headers=admin_headers)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('resourceType') == 'Bundle':
                log_success(f"Get Patient Complete Bundle (entries: {len(data.get('entry', []))})")
            else:
                log_fail("Get Patient Complete Bundle", "Response is not a bundle")
        else:
            log_fail("Get Patient Complete Bundle", resp.text)
    except Exception as e:
        log_fail("Get Patient Complete Bundle", str(e))

    # Search Resources
    try:
        resp = requests.get(f"{FHIR_URL}/search?type=Observation&patient=pat-001", headers=admin_headers)
        if resp.status_code == 200:
            log_success(f"Search Observations (found: {resp.json().get('returned')})")
        else:
            log_fail("Search Observations", resp.text)
    except Exception as e:
        log_fail("Search Observations", str(e))
        
    # Upload Bundle
    bundle_data = {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": [
            {
                "resource": {
                    "resourceType": "Observation",
                    "id": "new-obs-test",
                    "status": "final",
                    "code": {"text": "Test Obs"}
                }
            }
        ]
    }
    try:
        resp = requests.post(f"{FHIR_URL}/bundle/upload", json=bundle_data, headers=admin_headers)
        if resp.status_code == 201:
            log_success("Upload Bundle")
        else:
            log_fail("Upload Bundle", resp.text)
    except Exception as e:
        log_fail("Upload Bundle", str(e))

    # 3. MS3 INTEGRATION TEST
    log_section("MS3 INTEGRATION TEST")
    try:
        doc_data = {
            "document_type": "Medical Report",
            "extracted_data": {"patient_name": "Test", "diagnosis": "Test"}
        }
        resp = requests.post(f"{FHIR_URL}/document/process", json=doc_data, headers=doctor_headers)
        if resp.status_code == 201:
            log_success("Process Document (MS3 available)")
        elif resp.status_code == 503:
             log_success("Process Document (Graceful failure - MS3 unavailable as expected)")
        else:
            log_fail("Process Document", f"Unexpected status: {resp.status_code} - {resp.text}")
    except Exception as e:
        log_fail("Process Document", str(e))

    # 4. ADMIN TESTS
    log_section("ADMIN TESTS")
    try:
        resp = requests.get(f"{ADMIN_URL}/audit-logs?limit=5", headers=admin_headers)
        if resp.status_code == 200:
            log_success("Get Audit Logs")
        else:
            log_fail("Get Audit Logs", resp.text)
    except Exception as e:
        log_fail("Get Audit Logs", str(e))

if __name__ == "__main__":
    server_process = start_server()
    try:
        run_tests()
    finally:
        stop_server(server_process)
