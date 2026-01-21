from flask import Blueprint, request, jsonify, current_app
from fhir_service import FHIRService
from models import db, User
import logging
import time
import jwt
import datetime
from werkzeug.security import check_password_hash, generate_password_hash

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
    Authenticate and return a valid JWT signed with 'emr-secure-key-2025'.
    """
    try:
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
             return jsonify({"error": "Invalid credentials"}), 401

        # Generate Payload
        # Expiration: 24 hours
        expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        
        payload = {
            "sub": user.username,
            "role": user.role, 
            "can_upload": user.can_upload,
            "exp": expiration,
            "iat": datetime.datetime.utcnow()
        }

        # Sign with the same key used in dinesh_EMR-Application-Layer
        SECRET_KEY = "emr-secure-key-2025"
        
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({"tokens": {"access": token}}), 200

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": str(e)}), 500

@fhir_bp.route("/auth/users", methods=["GET"])
def get_users():
    """Return list of users."""
    try:
        users = User.query.all()
        return jsonify([u.to_dict() for u in users]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@fhir_bp.route("/auth/users", methods=["POST"])
def create_user():
    """Create a new user."""
    try:
        data = request.get_json()
        if not data or not data.get("username") or not data.get("password"):
             return jsonify({"error": "Missing username or password"}), 400
        
        if User.query.filter_by(username=data["username"]).first():
             return jsonify({"error": "Username already exists"}), 400

        new_user = User(
            username=data["username"],
            password_hash=generate_password_hash(data["password"]),
            role=data.get("role", "user"),
            can_upload=data.get("can_upload", False),
            created_at=datetime.datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({"status": "User created", "id": new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@fhir_bp.route("/auth/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    """Delete a user by ID."""
    try:
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
        return jsonify({"status": "User deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

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
        name_query = filters.get("name")
        
        limit = int(request.args.get("_count", 100))
        offset = int(request.args.get("_offset", 0))
        
        if name_query:
            # specialized search
            results = FHIRService.search_conditions_by_text(name_query, limit)
            return jsonify({"resources": results, "total": len(results)}), 200
        
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
