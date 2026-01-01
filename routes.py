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

# --- Authentication Routes (REMOVED) ---

# --- FHIR Routes ---

@fhir_bp.route("/Patient", methods=["GET"])
def search_patients():
    try:
        filters = request.args.to_dict()
        
        # Pagination
        limit = int(request.args.get("_count", 20))
        offset = int(request.args.get("_offset", 0))

        result = FHIRService.search_resources("Patient", filters, limit, offset)

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
            
        return jsonify(bundle), 200

    except Exception as e:
        logger.error(f"Error retrieving patient: {str(e)}")
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
