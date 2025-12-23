
# from flask import Blueprint, request, jsonify, current_app

# from auth_service import AuthService, token_required, role_required, permission_required
# from fhir_service import FHIRService
# from audit_service import AuditService
# from models import User, db

# import logging
# import time

# logger = logging.getLogger(__name__)

# # Define Blueprints
# auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
# fhir_bp = Blueprint("fhir", __name__, url_prefix="/api/fhir")
# admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")
# health_bp = Blueprint("health", __name__, url_prefix="/health")


# # --- Health Check ---
# @health_bp.route("/status", methods=["GET"])
# def health_check():
#     return jsonify({"status": "healthy", "service": "Data Access Service"}), 200


# # --- Authentication Routes ---
# @auth_bp.route("/login", methods=["POST"])
# def login():
#     data = request.get_json()

#     if not data or not data.get("username") or not data.get("password"):
#         return jsonify({"error": "Username and password required"}), 400

#     result = AuthService.authenticate(data["username"], data["password"])

#     if not result:
#         # Log failed attempt
#         AuditService.log_access(
#             user_id=None,
#             action="LOGIN_FAILED",
#             status_code=401,
#             error_message=f"Failed login for {data.get('username')}",
#         )
#         return jsonify({"error": "Invalid credentials"}), 401

#     # Log success
#     AuditService.log_access(
#         user_id=result["user"]["id"],
#         action="LOGIN_SUCCESS",
#         status_code=200,
#     )

#     return jsonify(result), 200


# @auth_bp.route("/logout", methods=["POST"])
# @token_required
# def logout():
#     auth_header = request.headers.get("Authorization")

#     if auth_header:
#         token = auth_header.split(" ")[1]
#         AuthService.revoke_token(token, request.user_id)

#     AuditService.log_access(
#         user_id=request.user_id,
#         action="LOGOUT",
#         status_code=200,
#     )
#     return jsonify({"message": "Logged out successfully"}), 200


# @auth_bp.route("/register", methods=["POST"])
# def register():
#     # Only allow registration in dev mode or via specific flow (simplified here)
#     data = request.get_json()

#     try:
#         user = AuthService.register_user(
#             username=data.get("username"),
#             email=data.get("email"),
#             password=data.get("password"),
#             role=data.get("role", "VIEWER"),
#             department=data.get("department"),
#         )
#         return jsonify(user), 201

#     except ValueError as e:
#         return jsonify({"error": str(e)}), 400

#     except Exception:
#         return jsonify({"error": "Registration failed"}), 500


# # --- FHIR Routes ---

# @fhir_bp.route("/Patient", methods=["GET"])
# @token_required
# @permission_required("Patient", "READ")
# def search_patients():
#     start_time = time.time()
#     try:
#         filters = request.args.to_dict()
#         user_id = request.user_id

#         # Security: Enforce "Own Data Only"
#         if getattr(request, "own_data_only", False):
#             user = User.query.get(user_id)
#             if not user or not user.fhir_patient_id:
#                 return jsonify({"error": "User not linked to a patient record"}), 403

#             # Force the filter to the user's patient ID
#             filters["patient_fhir_id"] = user.fhir_patient_id

#         # Pagination
#         limit = int(request.args.get("_count", 20))
#         offset = int(request.args.get("_offset", 0))

#         result = FHIRService.search_resources("Patient", filters, limit, offset)

#         AuditService.log_access(
#             user_id=user_id,
#             action="SEARCH",
#             resource_type="Patient",
#             status_code=200,
#             response_time_ms=(time.time() - start_time) * 1000,
#         )

#         return jsonify(result), 200

#     except Exception as e:
#         logger.error(f"Error searching patients: {str(e)}")
#         return jsonify({"error": str(e)}), 500


# @fhir_bp.route("/Patient/<patient_id>", methods=["GET"])
# @token_required
# @permission_required("Patient", "READ")
# def get_patient(patient_id):
#     start_time = time.time()
#     try:
#         # Security: Enforce "Own Data Only"
#         if getattr(request, "own_data_only", False):
#             user = User.query.get(request.user_id)
#             if not user.fhir_patient_id or user.fhir_patient_id != patient_id:
#                 AuditService.log_access(
#                     user_id=request.user_id,
#                     action="READ_DENIED",
#                     resource_type="Patient",
#                     fhir_id=patient_id,
#                     status_code=403,
#                     error_message="Attempted to access other patient's data",
#                 )
#                 return jsonify(
#                     {"error": "Access denied to this patient record"}
#                 ), 403

#         # Get Full Bundle
#         bundle = FHIRService.get_patient_bundle(patient_id)
#         if not bundle:
#             return jsonify({"error": "Patient not found"}), 404

#         AuditService.log_access(
#             user_id=request.user_id,
#             action="READ",
#             resource_type="Patient",
#             fhir_id=patient_id,
#             status_code=200,
#             response_time_ms=(time.time() - start_time) * 1000,
#         )

#         return jsonify(bundle), 200

#     except Exception as e:
#         logger.error(f"Error retrieving patient: {str(e)}")
#         return jsonify({"error": str(e)}), 500


# @fhir_bp.route("/Observation", methods=["GET"])
# @token_required
# @permission_required("Observation", "READ")
# def search_observations():
#     start_time = time.time()
#     try:
#         filters = request.args.to_dict()

#         # Security: Enforce "Own Data Only"
#         if getattr(request, "own_data_only", False):
#             user = User.query.get(request.user_id)
#             if not user.fhir_patient_id:
#                 return jsonify({"error": "User not linked to a patient record"}), 403
#             filters["patient_fhir_id"] = user.fhir_patient_id

#         limit = int(request.args.get("_count", 20))
#         offset = int(request.args.get("_offset", 0))

#         result = FHIRService.search_resources("Observation", filters, limit, offset)

#         AuditService.log_access(
#             user_id=request.user_id,
#             action="SEARCH",
#             resource_type="Observation",
#             status_code=200,
#         )

#         return jsonify(result), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# # --- NEW: Harmonization ingest endpoint ---

# @fhir_bp.route("/ingest", methods=["POST"])
# @token_required
# @permission_required("FHIRResource", "CREATE")  # configure PermissionMatrix for this
# def ingest_fhir_resource():
#     """
#     Endpoint for Harmonization layer to push FHIR data.
#     Expects JSON FHIR resource with resourceType and id.
#     Optional: patientFhirId, pseudonymId in body or query params.
#     """
#     start_time = time.time()
#     try:
#         data = request.get_json()
#         if not data:
#             return jsonify({"error": "Missing JSON body"}), 400

#         resource_type = data.get("resourceType")
#         fhir_id = data.get("id")
#         if not resource_type or not fhir_id:
#             return jsonify({"error": "Missing resourceType or id in FHIR data"}), 400

#         # Try to infer patient_fhir_id from subject.reference like "Patient/123"
#         patient_fhir_id = None
#         subject = data.get("subject")
#         if isinstance(subject, dict):
#             ref = subject.get("reference")
#             if ref and isinstance(ref, str) and ref.startswith("Patient/"):
#                 patient_fhir_id = ref.split("/", 1)[1]

#         # Allow explicit override
#         patient_fhir_id = (
#             request.args.get("patientFhirId")
#             or data.get("patientFhirId")
#             or patient_fhir_id
#         )

#         pseudonym_id = request.args.get("pseudonymId") or data.get("pseudonymId")

#         stored = FHIRService.store_fhir_resource(
#             fhir_data=data,
#             patient_fhir_id=patient_fhir_id,
#             pseudonym_id=pseudonym_id,
#         )

#         if not stored:
#             AuditService.log_access(
#                 user_id=request.user_id,
#                 action="CREATE",
#                 resource_type=resource_type,
#                 fhir_id=fhir_id,
#                 patient_fhir_id=patient_fhir_id,
#                 status_code=500,
#                 response_time_ms=(time.time() - start_time) * 1000,
#                 error_message="Failed to store FHIR resource",
#             )
#             return jsonify({"error": "Failed to store FHIR resource"}), 500

#         AuditService.log_access(
#             user_id=request.user_id,
#             action="CREATE",
#             resource_type=resource_type,
#             fhir_id=fhir_id,
#             patient_fhir_id=patient_fhir_id,
#             status_code=201,
#             response_time_ms=(time.time() - start_time) * 1000,
#         )

#         return (
#             jsonify(
#                 {
#                     "message": "FHIR resource stored successfully",
#                     "fhirId": fhir_id,
#                     "resourceType": resource_type,
#                     "patientFhirId": patient_fhir_id,
#                 }
#             ),
#             201,
#         )

#     except Exception as e:
#         logger.error(f"Error ingesting FHIR resource: {e}")
#         AuditService.log_access(
#             user_id=getattr(request, "user_id", None),
#             action="CREATE",
#             resource_type="FHIRResource",
#             status_code=500,
#             response_time_ms=(time.time() - start_time) * 1000,
#             error_message=str(e),
#         )
#         return jsonify({"error": str(e)}), 500


# # --- Admin Routes ---

# @admin_bp.route("/audit-logs", methods=["GET"])
# @token_required
# @role_required("ADMIN")
# def get_audit_logs():
#     try:
#         logs = AuditService.get_access_logs(
#             user_id=request.args.get("user_id"),
#             resource_type=request.args.get("resource_type"),
#         )
#         return jsonify(logs), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @admin_bp.route("/users", methods=["GET"])
# @token_required
# @role_required("ADMIN")
# def get_users():
#     users = User.query.all()
#     return jsonify([u.to_dict() for u in users]), 200


"""
Extended Routes - Integrates MS3 FHIR bundles with MS1 storage
Adds new endpoints for accepting transaction bundles from MS3
"""
from flask import request, jsonify
from functools import wraps
import logging
from fhir_service_extended import FHIRService  # CHANGED: Use extended service
from auth_service import AuthService
from access_service import AccessService  # Add import if needed

logger = logging.getLogger(__name__)


def token_required(f):
    """Decorator to check JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return {'error': 'Token required'}, 401
        
        user_id, user_role = AuthService.validate_token(token)
        if not user_id:
            return {'error': 'Invalid token'}, 401
        
        return f(user_id, user_role, *args, **kwargs)
    return decorated


def permission_required(resource_type, action):
    """Decorator to check resource permissions"""
    def decorator(f):
        @wraps(f)
        def decorated(user_id, user_role, *args, **kwargs):
            # Check permission
            if not AccessService.has_permission(user_role, resource_type, action):
                return {'error': f'Permission denied for {resource_type}:{action}'}, 403
            return f(user_id, user_role, *args, **kwargs)
        return decorated
    return decorator


# ===== EXISTING ENDPOINTS (Keep unchanged) =====

@token_required
@permission_required('Patient', 'READ')
def get_patient_bundle(user_id, user_role, patient_id):
    """GET /api/fhir/Patient/<patient_id> - Get patient with all related resources"""
    bundle = FHIRService.get_patient_bundle(patient_id)
    
    if not bundle:
        return {'error': 'Patient not found'}, 404
    
    return bundle, 200


@token_required
def get_resource(user_id, user_role, resource_type, resource_id):
    """GET /api/fhir/<resource_type>/<id> - Get specific resource"""
    resource = FHIRService.get_resource_by_id(resource_id)
    
    if not resource:
        return {'error': f'{resource_type} not found'}, 404
    
    return resource, 200


# ===== NEW ENDPOINTS FOR MS3 INTEGRATION =====

@token_required
@permission_required('Bundle', 'WRITE')
def upload_fhir_bundle(user_id, user_role):
    """
    POST /api/fhir/bundle/upload
    Accept transaction bundle from MS3 and store all resources.
    
    Request body: FHIR transaction Bundle (from MS3)
    Response: Stored bundle summary
    """
    try:
        # Get JSON data
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
        
        # Validate it's a FHIR Bundle
        if data.get('resourceType') != 'Bundle':
            return {'error': 'Invalid resource type, expected Bundle'}, 400
        
        # Store the bundle
        success = FHIRService.store_fhir_bundle(data)
        
        if not success:
            return {'error': 'Failed to store bundle'}, 500
        
        # Count resources stored
        num_resources = len(data.get('entry', []))
        
        return {
            'success': True,
            'message': f'Bundle with {num_resources} resources stored successfully',
            'bundle_type': data.get('type'),
            'resources_count': num_resources
        }, 201
        
    except Exception as e:
        logger.error(f"Error uploading bundle: {str(e)}")
        return {'error': f'Upload failed: {str(e)}'}, 500


@token_required
@permission_required('Bundle', 'READ')
def get_patient_complete(user_id, user_role, patient_id):
    """
    GET /api/fhir/patient/<patient_id>/complete
    Get COMPLETE patient data as searchset Bundle.
    Includes: Patient, Observations, Conditions, Medications, Procedures, Encounters.
    """
    try:
        bundle = FHIRService.get_patient_bundle(patient_id)
        
        if not bundle:
            return {'error': 'Patient not found'}, 404
        
        return bundle, 200
        
    except Exception as e:
        logger.error(f"Error getting patient bundle: {str(e)}")
        return {'error': 'Failed to retrieve patient data'}, 500


@token_required
@permission_required('Patient', 'READ')
def search_resources(user_id, user_role):
    """
    GET /api/fhir/search?type=<resource_type>&patient=<patient_id>&limit=<limit>&offset=<offset>
    Search for FHIR resources.
    """
    try:
        resource_type = request.args.get('type')
        patient_id = request.args.get('patient')
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        if not resource_type:
            return {'error': 'resource type required'}, 400
        
        filters = {}
        if patient_id:
            filters['patient_fhir_id'] = patient_id
        
        result = FHIRService.search_resources(resource_type, filters, limit, offset)
        
        return {
            'resourceType': resource_type,
            'total': result['total'],
            'returned': result['count'],
            'resources': result['resources']
        }, 200
        
    except Exception as e:
        logger.error(f"Error searching resources: {str(e)}")
        return {'error': 'Search failed'}, 500


@token_required
@permission_required('Patient', 'DELETE')
def delete_patient_data(user_id, user_role, patient_id):
    """
    DELETE /api/fhir/patient/<patient_id>
    Delete all data for a patient (GDPR right to be forgotten).
    WARNING: This is irreversible!
    """
    try:
        count = FHIRService.delete_patient_data(patient_id)
        
        return {
            'success': True,
            'message': f'Deleted {count} resources for patient {patient_id}',
            'deleted_count': count
        }, 200
        
    except Exception as e:
        logger.error(f"Error deleting patient: {str(e)}")
        return {'error': 'Deletion failed'}, 500


# ===== MS3 INTEGRATION ENDPOINT =====

@token_required
def process_document_and_store(user_id, user_role):
    """
    POST /api/fhir/document/process
    Accept extracted document JSON, call MS3 mapper, store resulting FHIR bundle.
    
    Request body: {
        "document_type": "Medical Report" | "Lab Report" | "Discharge Summary" | "Admission Slip",
        "extracted_data": { ... extracted JSON from MS2 ... }
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
        
        document_type = data.get('document_type')
        extracted_data = data.get('extracted_data')
        
        if not document_type or not extracted_data:
            return {
                'error': 'Missing document_type or extracted_data',
                'expected': {
                    'document_type': 'Medical Report | Lab Report | Discharge Summary | Admission Slip',
                    'extracted_data': '...'
                }
            }, 400
        
        # Call MS3 API to convert to FHIR
        try:
            import requests
            ms3_response = requests.post(
                'http://localhost:5005/api/v1/map',  # MS3 endpoint
                json={
                    'document_type': document_type,
                    **extracted_data
                }
            )
            
            if ms3_response.status_code != 200:
                return {
                    'error': f'MS3 mapping failed: {ms3_response.text}'
                }, 500
            
            # Get FHIR bundle from MS3
            fhir_bundle = ms3_response.json()
            
            # Store the bundle
            success = FHIRService.store_fhir_bundle(fhir_bundle)
            
            if not success:
                return {'error': 'Failed to store FHIR bundle'}, 500
            
            return {
                'success': True,
                'message': 'Document processed and stored successfully',
                'document_type': document_type,
                'resources_stored': len(fhir_bundle.get('entry', []))
            }, 201
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to MS3: {str(e)}")
            return {
                'error': f'MS3 service unavailable: {str(e)}',
                'hint': 'Make sure MS3 is running on localhost:5005'
            }, 503
        
    except Exception as e:
        logger.error(f"Error processing document: {str(e)}")
        return {'error': f'Processing failed: {str(e)}'}, 500


# ===== HEALTH CHECK =====

def health_check():
    """GET /api/health - Health check"""
    return {
        'status': 'healthy',
        'service': 'FHIR EMR Microservice',
        'endpoints': [
            'GET /api/fhir/Patient/<id>',
            'POST /api/fhir/bundle/upload',
            'GET /api/fhir/patient/<id>/complete',
            'POST /api/fhir/document/process',
            'DELETE /api/fhir/patient/<id>'
        ]
    }, 200


# ===== REGISTER ENDPOINTS =====

def register_routes(app):
    """Register all routes with Flask app"""
    
    # Existing endpoints
    app.add_url_rule('/api/fhir/Patient/<patient_id>', 'get_patient_bundle', get_patient_bundle, methods=['GET'])
    app.add_url_rule('/api/fhir/<resource_type>/<resource_id>', 'get_resource', get_resource, methods=['GET'])
    
    # New endpoints
    app.add_url_rule('/api/fhir/bundle/upload', 'upload_fhir_bundle', upload_fhir_bundle, methods=['POST'])
    app.add_url_rule('/api/fhir/patient/<patient_id>/complete', 'get_patient_complete', get_patient_complete, methods=['GET'])
    app.add_url_rule('/api/fhir/search', 'search_resources', search_resources, methods=['GET'])
    app.add_url_rule('/api/fhir/patient/<patient_id>', 'delete_patient_data', delete_patient_data, methods=['DELETE'])
    
    # MS3 integration
    app.add_url_rule('/api/fhir/document/process', 'process_document_and_store', process_document_and_store, methods=['POST'])
    
    # Health check
    app.add_url_rule('/api/health', 'health_check', health_check, methods=['GET'])