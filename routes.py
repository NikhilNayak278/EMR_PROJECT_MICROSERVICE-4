from flask import Blueprint, request, jsonify, current_app
from fhir_service import FHIRService
from models import db
import logging
import time

logger = logging.getLogger(__name__)

# Define Blueprints
fhir_bp = Blueprint("fhir", __name__, url_prefix="/api/fhir")
health_bp = Blueprint("health", __name__, url_prefix="/health")


# --- Health Check ---
@health_bp.route("/status", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "Data Access Service"}), 200

@fhir_bp.route("/auth/login", methods=["POST"])
def login():
    """
    Mock authentication endpoint.
    Returns a dummy token.
    """
    return jsonify({"tokens": {"access": "mock-token-123"}}), 200

@fhir_bp.route("/search", methods=["GET"])
def search_generic():
    """
    Generic search endpoint to handle dinesh-microservice's /api/fhir/search calls.
    Redirects or proxies to resource-specific search.
    """
    resource_type = request.args.get("type")
    if not resource_type:
        return jsonify({"error": "Missing 'type' parameter"}), 400
    
    # Map 'Patient' -> search_patients
    if resource_type == "Patient":
        return search_patients()
    
    # Fallback for other resources (Observation, etc) - reuse generic logic
    try:
        filters = request.args.to_dict()
        if "type" in filters: del filters["type"] # Remove meta-param
        
        limit = int(request.args.get("_count", request.args.get("limit", 20)))
        offset = int(request.args.get("_offset", 0))
        
        result = FHIRService.search_resources(resource_type, filters, limit, offset)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@fhir_bp.route("/confirm", methods=["POST"])
def confirm_bundle():
    """
    Endpoint to receive a confirmed FHIR Bundle.
    Splits the bundle and stores individual resources.
    Generates a unique Patient ID and links all resources to it.
    Maps pseudonym_id from request.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400
        
        # Extract pseudonym_id
        pseudonym_id = data.get("pseudonymId") # From dinesh_EMR injection
        
        bundle_type = data.get("resourceType")
        if bundle_type != "Bundle":
            # Fallback if single resource
             FHIRService.store_fhir_resource(data, pseudonym_id=pseudonym_id)
             return jsonify({"status": "Stored single resource"}), 201

        entries = data.get("entry", [])
        
        # 1. Find Patient to generate the Master ID
        generated_patient_id = None
        patient_entry = None
        
        for entry in entries:
            res = entry.get("resource", {})
            if res.get("resourceType") == "Patient":
                patient_entry = res
                break
        
        if patient_entry:
            # Store Patient first, which generates the ID
            generated_patient_id = FHIRService.store_fhir_resource(patient_entry, pseudonym_id=pseudonym_id)
        else:
            # Fallback: Generate one if no patient resource found (unlikely in this flow)
            import uuid
            generated_patient_id = str(uuid.uuid4())

        # 2. Store all resources linked to this Patient ID
        count = 0
        for entry in entries:
            res = entry.get("resource", {})
            rtype = res.get("resourceType")
            
            if rtype == "Patient":
                continue # Already handled
                
            # Update references to the new Patient ID
            # Assuming standard "subject": {"reference": "Patient/..."}
            if "subject" in res and "reference" in res["subject"]:
                ref = res["subject"]["reference"]
                if ref.startswith("Patient/"):
                    res["subject"]["reference"] = f"Patient/{generated_patient_id}"
            
            # Also update "patient" field if present (e.g. some resources use 'patient')
            if "patient" in res and "reference" in res["patient"]:
                 ref = res["patient"]["reference"]
                 if ref.startswith("Patient/"):
                    res["patient"]["reference"] = f"Patient/{generated_patient_id}"

            FHIRService.store_fhir_resource(res, patient_fhir_id=generated_patient_id, pseudonym_id=pseudonym_id)
            count += 1

        return jsonify({"status": "success", "patient_id": generated_patient_id, "resources_stored": count + 1}), 201

    except Exception as e:
         logger.error(f"Confirm Error: {e}")
         return jsonify({"error": str(e)}), 500


@fhir_bp.route("/Patient", methods=["GET"])
def search_patients():
    try:
        filters = request.args.to_dict()
        
        # Pagination
        limit = int(request.args.get("_count", 20))
        offset = int(request.args.get("_offset", 0))

        result = FHIRService.search_resources("Patient", filters, limit, offset)
        print(result)
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error searching patients: {str(e)}")
        return jsonify({"error": str(e)}), 500


@fhir_bp.route("/Patient/<patient_id>", methods=["GET"])
def get_patient(patient_id):
    try:
        # Get Full Bundle
        bundle = FHIRService.get_patient_bundle(patient_id)
        if not bundle:
            return jsonify({"error": "Patient not found"}), 404
            
        print(bundle)
        return jsonify(bundle), 200

    except Exception as e:
        logger.error(f"Error retrieving patient: {str(e)}")
        return jsonify({"error": str(e)}), 500


@fhir_bp.route("/Condition", methods=["GET"])
def search_conditions():
    try:
        filters = request.args.to_dict()
        
        limit = int(request.args.get("_count", 100))
        offset = int(request.args.get("_offset", 0))
        
        result = FHIRService.search_resources("Condition", filters, limit, offset)
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@fhir_bp.route("/Observation", methods=["GET"])
def search_observations():
    try:
        filters = request.args.to_dict()
        
        limit = int(request.args.get("_count", 20))
        offset = int(request.args.get("_offset", 0))
        
        result = FHIRService.search_resources("Observation", filters, limit, offset)
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@fhir_bp.route("/<resource_type>", methods=["POST"])
def create_resource(resource_type):
    """
    Generic endpoint to create any FHIR resource.
    Matches the pattern: POST /api/fhir/{resourceType}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400

        # Validate resource type matches body
        if data.get("resourceType") != resource_type:
            # Allow fallback if body has it but URL is different, but user usually expects match
            pass # Relaxed check

        fhir_id = data.get("id")
        if not fhir_id:
             return jsonify({"error": "Missing id in FHIR data"}), 400

        # Try to infer patient_fhir_id
        patient_fhir_id = None
        subject = data.get("subject")
        if isinstance(subject, dict):
            ref = subject.get("reference")
            if ref and isinstance(ref, str) and ref.startswith("Patient/"):
                patient_fhir_id = ref.split("/", 1)[1]
        
        if not patient_fhir_id:
            patient_ref = data.get("patient")
            if isinstance(patient_ref, dict):
                ref = patient_ref.get("reference")
                if ref and isinstance(ref, str) and ref.startswith("Patient/"):
                    patient_fhir_id = ref.split("/", 1)[1]

        if resource_type == "Patient":
            patient_fhir_id = fhir_id

        # Allow explicit override
        patient_fhir_id = (
            request.args.get("patientFhirId")
            or data.get("patientFhirId")
            or patient_fhir_id
        )

        pseudonym_id = request.args.get("pseudonymId") or data.get("pseudonymId")

        # Reuse the store logic
        stored = FHIRService.store_fhir_resource(
            fhir_data=data,
            patient_fhir_id=patient_fhir_id,
            pseudonym_id=pseudonym_id,
        )

        if not stored:
             return jsonify({"error": "Failed to store FHIR resource"}), 500

        return jsonify(data), 201

    except Exception as e:
        logger.error(f"Error creating {resource_type}: {e}")
        return jsonify({"error": str(e)}), 500
