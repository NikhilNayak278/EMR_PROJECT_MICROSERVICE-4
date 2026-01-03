"""
Extended Routes - Integrates MS3 FHIR bundles with MS1 storage
Adds new endpoints for accepting transaction bundles from MS3
"""
from flask import Blueprint, request, jsonify
from functools import wraps
import logging
from fhir_service_extended import FHIRService
from auth_service import AuthService
from access_service import AccessService
from audit_service import AuditService

logger = logging.getLogger(__name__)

# Create Blueprints
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
fhir_bp = Blueprint('fhir', __name__, url_prefix='/api/fhir')
admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')
health_bp = Blueprint('health', __name__, url_prefix='/api')


def token_required(f):
    """Decorator to check JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # DEV MODE CHECK
        import os
        if os.environ.get('FLASK_ENV', 'development') == 'development':
            # Check if token is present, if not, use dummy admin
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            if not token:
                logger.warning("DEV MODE: Bypassing auth with dummy admin user")
                return f('dev-admin', 'ADMIN', *args, **kwargs)
        
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return {'error': 'Token required'}, 401
        
        payload = AuthService.verify_token(token)
        if not payload:
            return {'error': 'Invalid token'}, 401
        
        user_id = payload.get('user_id')
        user_role = payload.get('role')
        
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


# ===== AUTHENTICATION ENDPOINTS =====

@auth_bp.route('/login', methods=['POST'])
def login():
    """POST /api/auth/login - Login user and get JWT tokens"""
    try:
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'error': 'Username and password required'}, 400
        
        # Authenticate user
        user = AuthService.authenticate(username, password)
        
        if not user:
            AuditService.log_access(None, 'LOGIN', None, None, status_code=401, error_message='Invalid credentials')
            return {'error': 'Invalid username or password'}, 401
        
        # Generate tokens
        tokens = AuthService.generate_tokens(user.id, user.role)
        
        # Log successful login
        AuditService.log_access(user.id, 'LOGIN', None, None, status_code=200)
        
        return {
            'success': True,
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'fhir_patient_id': user.fhir_patient_id
            }
        }, 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return {'error': f'Login failed: {str(e)}'}, 500


@auth_bp.route('/register', methods=['POST'])
def register():
    """POST /api/auth/register - Register new user"""
    try:
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'VIEWER')
        
        if not username or not email or not password:
            return {'error': 'Username, email, and password required'}, 400
        
        # Register user
        user = AuthService.register_user(username, email, password, role)
        
        if not user:
            return {'error': 'User already exists'}, 409
        
        AuditService.log_access(user.id, 'REGISTER', None, None, status_code=201)
        
        return {
            'success': True,
            'message': f'User {username} registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        }, 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return {'error': f'Registration failed: {str(e)}'}, 500


@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """POST /api/auth/refresh - Refresh access token using refresh token"""
    try:
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
        
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return {'error': 'Refresh token required'}, 400
        
        # Verify refresh token
        payload = AuthService.verify_token(refresh_token)
        
        if not payload:
            return {'error': 'Invalid or expired refresh token'}, 401
        
        # Generate new access token
        user_id = payload.get('user_id')
        user_role = payload.get('role')
        
        new_tokens = AuthService.generate_tokens(user_id, user_role)
        
        return {
            'success': True,
            'access_token': new_tokens['access_token'],
            'refresh_token': new_tokens['refresh_token']
        }, 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return {'error': f'Token refresh failed: {str(e)}'}, 500


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(user_id, user_role):
    """POST /api/auth/logout - Logout user and revoke token"""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return {'error': 'No token provided'}, 400
        
        # Revoke token
        AuthService.revoke_token(token)
        
        # Log logout
        AuditService.log_access(user_id, 'LOGOUT', None, None, status_code=200)
        
        return {
            'success': True,
            'message': 'Logged out successfully'
        }, 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return {'error': f'Logout failed: {str(e)}'}, 500


# ===== EXISTING ENDPOINTS =====

@fhir_bp.route('/Patient/<patient_id>', methods=['GET'])
@token_required
@permission_required('Patient', 'READ')
def get_patient_bundle(user_id, user_role, patient_id):
    """GET /api/fhir/Patient/<patient_id> - Get patient with all related resources"""
    try:
        bundle = FHIRService.get_patient_bundle(patient_id)
        
        if not bundle:
            AuditService.log_access(user_id, 'READ', 'Patient', patient_id, status_code=404)
            return {'error': 'Patient not found'}, 404
        
        AuditService.log_access(user_id, 'READ', 'Patient', patient_id, status_code=200)
        return bundle, 200
    except Exception as e:
        logger.error(f"Error getting patient bundle: {str(e)}")
        AuditService.log_access(user_id, 'READ', 'Patient', patient_id, status_code=500, error_message=str(e))
        return {'error': 'Failed to retrieve patient'}, 500


@fhir_bp.route('/<resource_type>/<resource_id>', methods=['GET'])
@token_required
@permission_required('Patient', 'READ')
def get_resource(user_id, user_role, resource_type, resource_id):
    """GET /api/fhir/<resource_type>/<id> - Get specific resource"""
    try:
        resource = FHIRService.get_resource_by_id(resource_id)
        
        if not resource:
            AuditService.log_access(user_id, 'READ', resource_type, resource_id, status_code=404)
            return {'error': f'{resource_type} not found'}, 404
        
        AuditService.log_access(user_id, 'READ', resource_type, resource_id, status_code=200)
        return resource, 200
    except Exception as e:
        logger.error(f"Error getting resource: {str(e)}")
        AuditService.log_access(user_id, 'READ', resource_type, resource_id, status_code=500, error_message=str(e))
        return {'error': 'Failed to retrieve resource'}, 500


        return {'error': 'Failed to retrieve resource'}, 500


@fhir_bp.route('/confirm', methods=['POST'])
@token_required
def confirm_and_save_bundle(user_id, user_role):
    """
    POST /api/fhir/confirm
    Confirm and save a harmonized FHIR bundle.
    Unlike bundle/upload, this is specifically for the user-confirmed flow.
    """
    try:
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
            
        # Optional: Add extra validation here if needed
        
        success = FHIRService.store_fhir_bundle(data)
        
        if success:
            AuditService.log_access(user_id, 'CREATE', 'Bundle', None, status_code=201)
            return {
                'success': True,
                'message': 'Bundle confirmed and saved successfully',
                'count': len(data.get('entry', []))
            }, 201
        else:
            return {'error': 'Failed to save bundle'}, 500
            
    except Exception as e:
        logger.error(f"Error in confirm and save: {str(e)}")
        return {'error': str(e)}, 500


# ===== NEW ENDPOINTS FOR MS3 INTEGRATION =====

@fhir_bp.route('/bundle/upload', methods=['POST'])
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
            AuditService.log_access(user_id, 'CREATE', 'Bundle', None, status_code=400)
            return {'error': 'No data provided'}, 400
        
        # Validate it's a FHIR Bundle
        if data.get('resourceType') != 'Bundle':
            AuditService.log_access(user_id, 'CREATE', 'Bundle', None, status_code=400)
            return {'error': 'Invalid resource type, expected Bundle'}, 400
        
        # Store the bundle
        success = FHIRService.store_fhir_bundle(data)
        
        if not success:
            AuditService.log_access(user_id, 'CREATE', 'Bundle', None, status_code=500)
            return {'error': 'Failed to store bundle'}, 500
        
        # Count resources stored
        num_resources = len(data.get('entry', []))
        
        AuditService.log_access(user_id, 'CREATE', 'Bundle', None, status_code=201)
        return {
            'success': True,
            'message': f'Bundle with {num_resources} resources stored successfully',
            'bundle_type': data.get('type'),
            'resources_count': num_resources
        }, 201
        
    except Exception as e:
        logger.error(f"Error uploading bundle: {str(e)}")
        AuditService.log_access(user_id, 'CREATE', 'Bundle', None, status_code=500, error_message=str(e))
        return {'error': f'Upload failed: {str(e)}'}, 500


@fhir_bp.route('/patient/<patient_id>/complete', methods=['GET'])
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
            AuditService.log_access(user_id, 'READ', 'Patient', patient_id, status_code=404)
            return {'error': 'Patient not found'}, 404
        
        AuditService.log_access(user_id, 'READ', 'Patient', patient_id, status_code=200)
        return bundle, 200
        
    except Exception as e:
        logger.error(f"Error getting patient bundle: {str(e)}")
        AuditService.log_access(user_id, 'READ', 'Patient', patient_id, status_code=500, error_message=str(e))
        return {'error': 'Failed to retrieve patient data'}, 500


@fhir_bp.route('/search', methods=['GET'])
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
            AuditService.log_access(user_id, 'SEARCH', resource_type, None, status_code=400)
            return {'error': 'resource type required'}, 400
        
        filters = {}
        if patient_id:
            filters['patient_fhir_id'] = patient_id
        
        result = FHIRService.search_resources(resource_type, filters, limit, offset)
        
        AuditService.log_access(user_id, 'SEARCH', resource_type, None, status_code=200)
        return {
            'resourceType': resource_type,
            'total': result['total'],
            'returned': result['count'],
            'resources': result['resources']
        }, 200
        
    except Exception as e:
        logger.error(f"Error searching resources: {str(e)}")
        AuditService.log_access(user_id, 'SEARCH', resource_type, None, status_code=500, error_message=str(e))
        return {'error': f'Search failed: {str(e)}'}, 500


@fhir_bp.route('/patient/<patient_id>', methods=['DELETE'])
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
        
        AuditService.log_access(user_id, 'DELETE', 'Patient', patient_id, status_code=200)
        return {
            'success': True,
            'message': f'Deleted {count} resources for patient {patient_id}',
            'deleted_count': count
        }, 200
        
    except Exception as e:
        logger.error(f"Error deleting patient: {str(e)}")
        AuditService.log_access(user_id, 'DELETE', 'Patient', patient_id, status_code=500, error_message=str(e))
        return {'error': 'Deletion failed'}, 500


# ===== MS3 INTEGRATION ENDPOINT =====

@fhir_bp.route('/document/process', methods=['POST'])
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
            AuditService.log_access(user_id, 'CREATE', 'Document', None, status_code=400)
            return {'error': 'No data provided'}, 400
        
        document_type = data.get('document_type')
        extracted_data = data.get('extracted_data')
        
        if not document_type or not extracted_data:
            AuditService.log_access(user_id, 'CREATE', 'Document', None, status_code=400)
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
                },
                timeout=30
            )
            
            if ms3_response.status_code != 200:
                AuditService.log_access(user_id, 'CREATE', 'Document', None, status_code=500)
                return {
                    'error': f'MS3 mapping failed: {ms3_response.text}'
                }, 500
            
            # Get FHIR bundle from MS3
            fhir_bundle = ms3_response.json()
            
            # Store the bundle
            success = FHIRService.store_fhir_bundle(fhir_bundle)
            
            if not success:
                AuditService.log_access(user_id, 'CREATE', 'Document', None, status_code=500)
                return {'error': 'Failed to store FHIR bundle'}, 500
            
            AuditService.log_access(user_id, 'CREATE', 'Document', None, status_code=201)
            return {
                'success': True,
                'message': 'Document processed and stored successfully',
                'document_type': document_type,
                'resources_stored': len(fhir_bundle.get('entry', []))
            }, 201
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to MS3: {str(e)}")
            AuditService.log_access(user_id, 'CREATE', 'Document', None, status_code=503, error_message=str(e))
            return {
                'error': f'MS3 service unavailable: {str(e)}',
                'hint': 'Make sure MS3 is running on localhost:5005'
            }, 503
        
    except Exception as e:
        logger.error(f"Error processing document: {str(e)}")
        AuditService.log_access(user_id, 'CREATE', 'Document', None, status_code=500, error_message=str(e))
        return {'error': f'Processing failed: {str(e)}'}, 500


# ===== HEALTH CHECK =====

@health_bp.route('/health', methods=['GET'])
def health_check():
    """GET /api/health - Health check"""
    return {
        'status': 'healthy',
        'service': 'FHIR Data Access Microservice',
        'version': '2.0',
        'endpoints': [
            'GET /api/fhir/Patient/<id>',
            'GET /api/fhir/<resource_type>/<id>',
            'POST /api/fhir/bundle/upload',
            'GET /api/fhir/patient/<id>/complete',
            'GET /api/fhir/search',
            'POST /api/fhir/document/process',
            'DELETE /api/fhir/patient/<id>',
            'GET /api/health'
        ]
    }, 200


# ===== ADMIN ENDPOINTS =====

@admin_bp.route('/audit-logs', methods=['GET'])
# @token_required
@permission_required('*', '*')  # Admin only
def get_audit_logs(user_id, user_role):
    """GET /api/admin/audit-logs - Get system audit logs"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        resource_type = request.args.get('resource_type')
        user_filter = request.args.get('user_id', type=int)
        
        logs = AuditService.get_access_logs(user_filter, resource_type, limit, offset)
        
        return {
            'success': True,
            'count': len(logs),
            'logs': logs
        }, 200
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {str(e)}")
        return {'error': 'Failed to retrieve logs'}, 500


@admin_bp.route('/user-activity/<int:target_user_id>', methods=['GET'])
# @token_required
@permission_required('*', '*') # Admin only
def get_user_activity(user_id, user_role, target_user_id):
    """GET /api/admin/user-activity/<id> - Get specific user activity"""
    try:
        days = request.args.get('days', 30, type=int)
        
        activity = AuditService.get_user_activity(target_user_id, days)
        
        if not activity:
            return {'error': 'User not found or no activity'}, 404
            
        return activity, 200
        
    except Exception as e:
        logger.error(f"Error getting user activity: {str(e)}")
        return {'error': 'Failed to retrieve user activity'}, 500