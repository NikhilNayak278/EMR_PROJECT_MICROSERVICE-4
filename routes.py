

# from flask import Blueprint, request, jsonify, current_app
# from auth_service import AuthService, token_required, role_required, permission_required
# from fhir_service import FHIRService
# from audit_service import AuditService
# from models import User, db
# import logging
# import time

# logger = logging.getLogger(__name__)

# # Define Blueprints
# auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
# fhir_bp = Blueprint('fhir', __name__, url_prefix='/api/fhir')
# admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')
# health_bp = Blueprint('health', __name__, url_prefix='/health')


# # --- Health Check ---
# @health_bp.route('/status', methods=['GET'])
# def health_check():
#     return jsonify({'status': 'healthy', 'service': 'Data Access Service'}), 200


# # --- Authentication Routes ---
# @auth_bp.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     if not data or not data.get('username') or not data.get('password'):
#         return jsonify({'error': 'Username and password required'}), 400
    
#     result = AuthService.authenticate(data['username'], data['password'])
    
#     if not result:
#         # Log failed attempt
#         AuditService.log_access(
#             user_id=None, 
#             action='LOGIN_FAILED', 
#             status_code=401,
#             error_message=f"Failed login for {data.get('username')}"
#         )
#         return jsonify({'error': 'Invalid credentials'}), 401
    
#     # Log success
#     AuditService.log_access(
#         user_id=result['user']['id'], 
#         action='LOGIN_SUCCESS', 
#         status_code=200
#     )
    
#     return jsonify(result), 200

# @auth_bp.route('/logout', methods=['POST'])
# @token_required
# def logout():
#     auth_header = request.headers.get('Authorization')
#     if auth_header:
#         token = auth_header.split(" ")[1]
#         AuthService.revoke_token(token, request.user_id)
        
#     AuditService.log_access(user_id=request.user_id, action='LOGOUT', status_code=200)
#     return jsonify({'message': 'Logged out successfully'}), 200

# @auth_bp.route('/register', methods=['POST'])
# def register():
#     # Only allow registration in dev mode or via specific flow (simplified here)
#     data = request.get_json()
#     try:
#         user = AuthService.register_user(
#             username=data.get('username'),
#             email=data.get('email'),
#             password=data.get('password'),
#             role=data.get('role', 'VIEWER'),
#             department=data.get('department')
#         )
#         return jsonify(user), 201
#     except ValueError as e:
#         return jsonify({'error': str(e)}), 400
#     except Exception as e:
#         return jsonify({'error': 'Registration failed'}), 500


# # --- FHIR Routes ---

# @fhir_bp.route('/Patient', methods=['GET'])
# @token_required
# @permission_required('Patient', 'READ')
# def search_patients():
#     start_time = time.time()
#     try:
#         filters = request.args.to_dict()
#         user_id = request.user_id
        
#         # Security: Enforce "Own Data Only"
#         if getattr(request, 'own_data_only', False):
#             user = User.query.get(user_id)
#             if not user or not user.fhir_patient_id:
#                 return jsonify({'error': 'User not linked to a patient record'}), 403
            
#             # Force the filter to the user's patient ID
#             filters['patient_fhir_id'] = user.fhir_patient_id
        
#         # Pagination
#         limit = int(request.args.get('_count', 20))
#         offset = int(request.args.get('_offset', 0))
        
#         result = FHIRService.search_resources('Patient', filters, limit, offset)
        
#         AuditService.log_access(
#             user_id=user_id,
#             action='SEARCH',
#             resource_type='Patient',
#             status_code=200,
#             response_time_ms=(time.time() - start_time) * 1000
#         )
        
#         return jsonify(result), 200
        
#     except Exception as e:
#         logger.error(f"Error searching patients: {str(e)}")
#         return jsonify({'error': str(e)}), 500


# @fhir_bp.route('/Patient/<patient_id>', methods=['GET'])
# @token_required
# @permission_required('Patient', 'READ')
# def get_patient(patient_id):
#     start_time = time.time()
#     try:
#         # Security: Enforce "Own Data Only"
#         if getattr(request, 'own_data_only', False):
#             user = User.query.get(request.user_id)
#             if not user.fhir_patient_id or user.fhir_patient_id != patient_id:
#                 AuditService.log_access(
#                     user_id=request.user_id,
#                     action='READ_DENIED',
#                     resource_type='Patient',
#                     fhir_id=patient_id,
#                     status_code=403,
#                     error_message="Attempted to access other patient's data"
#                 )
#                 return jsonify({'error': 'Access denied to this patient record'}), 403

#         # Get Full Bundle
#         bundle = FHIRService.get_patient_bundle(patient_id)
        
#         if not bundle:
#             return jsonify({'error': 'Patient not found'}), 404
            
#         AuditService.log_access(
#             user_id=request.user_id,
#             action='READ',
#             resource_type='Patient',
#             fhir_id=patient_id,
#             status_code=200,
#             response_time_ms=(time.time() - start_time) * 1000
#         )
        
#         return jsonify(bundle), 200
        
#     except Exception as e:
#         logger.error(f"Error retrieving patient: {str(e)}")
#         return jsonify({'error': str(e)}), 500


# @fhir_bp.route('/Observation', methods=['GET'])
# @token_required
# @permission_required('Observation', 'READ')
# def search_observations():
#     start_time = time.time()
#     try:
#         filters = request.args.to_dict()
        
#         # Security: Enforce "Own Data Only"
#         if getattr(request, 'own_data_only', False):
#             user = User.query.get(request.user_id)
#             if not user.fhir_patient_id:
#                 return jsonify({'error': 'User not linked to a patient record'}), 403
#             filters['patient_fhir_id'] = user.fhir_patient_id
            
#         limit = int(request.args.get('_count', 20))
#         offset = int(request.args.get('_offset', 0))
        
#         result = FHIRService.search_resources('Observation', filters, limit, offset)
        
#         AuditService.log_access(
#             user_id=request.user_id,
#             action='SEARCH',
#             resource_type='Observation',
#             status_code=200
#         )
        
#         return jsonify(result), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500


# # --- Admin Routes ---
# @admin_bp.route('/audit-logs', methods=['GET'])
# @token_required
# @role_required('ADMIN')
# def get_audit_logs():
#     try:
#         logs = AuditService.get_access_logs(
#             user_id=request.args.get('user_id'),
#             resource_type=request.args.get('resource_type')
#         )
#         return jsonify(logs), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# @admin_bp.route('/users', methods=['GET'])
# @token_required
# @role_required('ADMIN')
# def get_users():
#     users = User.query.all()
#     return jsonify([u.to_dict() for u in users]), 200

from flask import Blueprint, request, jsonify, current_app

from auth_service import AuthService, token_required, role_required, permission_required
from fhir_service import FHIRService
from audit_service import AuditService
from models import User, db

import logging
import time

logger = logging.getLogger(__name__)

# Define Blueprints
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
fhir_bp = Blueprint("fhir", __name__, url_prefix="/api/fhir")
admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")
health_bp = Blueprint("health", __name__, url_prefix="/health")


# --- Health Check ---
@health_bp.route("/status", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "Data Access Service"}), 200


# --- Authentication Routes ---
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password required"}), 400

    result = AuthService.authenticate(data["username"], data["password"])

    if not result:
        # Log failed attempt
        AuditService.log_access(
            user_id=None,
            action="LOGIN_FAILED",
            status_code=401,
            error_message=f"Failed login for {data.get('username')}",
        )
        return jsonify({"error": "Invalid credentials"}), 401

    # Log success
    AuditService.log_access(
        user_id=result["user"]["id"],
        action="LOGIN_SUCCESS",
        status_code=200,
    )

    return jsonify(result), 200


@auth_bp.route("/logout", methods=["POST"])
@token_required
def logout():
    auth_header = request.headers.get("Authorization")

    if auth_header:
        token = auth_header.split(" ")[1]
        AuthService.revoke_token(token, request.user_id)

    AuditService.log_access(
        user_id=request.user_id,
        action="LOGOUT",
        status_code=200,
    )
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/register", methods=["POST"])
def register():
    # Only allow registration in dev mode or via specific flow (simplified here)
    data = request.get_json()

    try:
        user = AuthService.register_user(
            username=data.get("username"),
            email=data.get("email"),
            password=data.get("password"),
            role=data.get("role", "VIEWER"),
            department=data.get("department"),
        )
        return jsonify(user), 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    except Exception:
        return jsonify({"error": "Registration failed"}), 500


# --- FHIR Routes ---

@fhir_bp.route("/Patient", methods=["GET"])
@token_required
@permission_required("Patient", "READ")
def search_patients():
    start_time = time.time()
    try:
        filters = request.args.to_dict()
        user_id = request.user_id

        # Security: Enforce "Own Data Only"
        if getattr(request, "own_data_only", False):
            user = User.query.get(user_id)
            if not user or not user.fhir_patient_id:
                return jsonify({"error": "User not linked to a patient record"}), 403

            # Force the filter to the user's patient ID
            filters["patient_fhir_id"] = user.fhir_patient_id

        # Pagination
        limit = int(request.args.get("_count", 20))
        offset = int(request.args.get("_offset", 0))

        result = FHIRService.search_resources("Patient", filters, limit, offset)

        AuditService.log_access(
            user_id=user_id,
            action="SEARCH",
            resource_type="Patient",
            status_code=200,
            response_time_ms=(time.time() - start_time) * 1000,
        )

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error searching patients: {str(e)}")
        return jsonify({"error": str(e)}), 500


@fhir_bp.route("/Patient/<patient_id>", methods=["GET"])
@token_required
@permission_required("Patient", "READ")
def get_patient(patient_id):
    start_time = time.time()
    try:
        # Security: Enforce "Own Data Only"
        if getattr(request, "own_data_only", False):
            user = User.query.get(request.user_id)
            if not user.fhir_patient_id or user.fhir_patient_id != patient_id:
                AuditService.log_access(
                    user_id=request.user_id,
                    action="READ_DENIED",
                    resource_type="Patient",
                    fhir_id=patient_id,
                    status_code=403,
                    error_message="Attempted to access other patient's data",
                )
                return jsonify(
                    {"error": "Access denied to this patient record"}
                ), 403

        # Get Full Bundle
        bundle = FHIRService.get_patient_bundle(patient_id)
        if not bundle:
            return jsonify({"error": "Patient not found"}), 404

        AuditService.log_access(
            user_id=request.user_id,
            action="READ",
            resource_type="Patient",
            fhir_id=patient_id,
            status_code=200,
            response_time_ms=(time.time() - start_time) * 1000,
        )

        return jsonify(bundle), 200

    except Exception as e:
        logger.error(f"Error retrieving patient: {str(e)}")
        return jsonify({"error": str(e)}), 500


@fhir_bp.route("/Observation", methods=["GET"])
@token_required
@permission_required("Observation", "READ")
def search_observations():
    start_time = time.time()
    try:
        filters = request.args.to_dict()

        # Security: Enforce "Own Data Only"
        if getattr(request, "own_data_only", False):
            user = User.query.get(request.user_id)
            if not user.fhir_patient_id:
                return jsonify({"error": "User not linked to a patient record"}), 403
            filters["patient_fhir_id"] = user.fhir_patient_id

        limit = int(request.args.get("_count", 20))
        offset = int(request.args.get("_offset", 0))

        result = FHIRService.search_resources("Observation", filters, limit, offset)

        AuditService.log_access(
            user_id=request.user_id,
            action="SEARCH",
            resource_type="Observation",
            status_code=200,
        )

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- NEW: Harmonization ingest endpoint ---

@fhir_bp.route("/ingest", methods=["POST"])
@token_required
@permission_required("FHIRResource", "CREATE")  # configure PermissionMatrix for this
def ingest_fhir_resource():
    """
    Endpoint for Harmonization layer to push FHIR data.
    Expects JSON FHIR resource with resourceType and id.
    Optional: patientFhirId, pseudonymId in body or query params.
    """
    start_time = time.time()
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400

        resource_type = data.get("resourceType")
        fhir_id = data.get("id")
        if not resource_type or not fhir_id:
            return jsonify({"error": "Missing resourceType or id in FHIR data"}), 400

        # Try to infer patient_fhir_id from subject.reference like "Patient/123"
        patient_fhir_id = None
        subject = data.get("subject")
        if isinstance(subject, dict):
            ref = subject.get("reference")
            if ref and isinstance(ref, str) and ref.startswith("Patient/"):
                patient_fhir_id = ref.split("/", 1)[1]

        # Allow explicit override
        patient_fhir_id = (
            request.args.get("patientFhirId")
            or data.get("patientFhirId")
            or patient_fhir_id
        )

        pseudonym_id = request.args.get("pseudonymId") or data.get("pseudonymId")

        stored = FHIRService.store_fhir_resource(
            fhir_data=data,
            patient_fhir_id=patient_fhir_id,
            pseudonym_id=pseudonym_id,
        )

        if not stored:
            AuditService.log_access(
                user_id=request.user_id,
                action="CREATE",
                resource_type=resource_type,
                fhir_id=fhir_id,
                patient_fhir_id=patient_fhir_id,
                status_code=500,
                response_time_ms=(time.time() - start_time) * 1000,
                error_message="Failed to store FHIR resource",
            )
            return jsonify({"error": "Failed to store FHIR resource"}), 500

        AuditService.log_access(
            user_id=request.user_id,
            action="CREATE",
            resource_type=resource_type,
            fhir_id=fhir_id,
            patient_fhir_id=patient_fhir_id,
            status_code=201,
            response_time_ms=(time.time() - start_time) * 1000,
        )

        return (
            jsonify(
                {
                    "message": "FHIR resource stored successfully",
                    "fhirId": fhir_id,
                    "resourceType": resource_type,
                    "patientFhirId": patient_fhir_id,
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"Error ingesting FHIR resource: {e}")
        AuditService.log_access(
            user_id=getattr(request, "user_id", None),
            action="CREATE",
            resource_type="FHIRResource",
            status_code=500,
            response_time_ms=(time.time() - start_time) * 1000,
            error_message=str(e),
        )
        return jsonify({"error": str(e)}), 500


# --- Admin Routes ---

@admin_bp.route("/audit-logs", methods=["GET"])
@token_required
@role_required("ADMIN")
def get_audit_logs():
    try:
        logs = AuditService.get_access_logs(
            user_id=request.args.get("user_id"),
            resource_type=request.args.get("resource_type"),
        )
        return jsonify(logs), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_bp.route("/users", methods=["GET"])
@token_required
@role_required("ADMIN")
def get_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200
