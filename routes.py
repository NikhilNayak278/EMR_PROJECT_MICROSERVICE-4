"""
API Routes for Data Access Service
"""
import logging
from flask import Blueprint, request, jsonify
from functools import wraps
from models import db, FHIRResource, User, AccessLog
from auth_service import AuthService
from fhir_service import FHIRService
from audit_service import AuditService
import time

logger = logging.getLogger(__name__)

# Create blueprints
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
fhir_bp = Blueprint('fhir', __name__, url_prefix='/api/fhir')
admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')
health_bp = Blueprint('health', __name__, url_prefix='/api')


# ============================================
# DECORATORS
# ============================================

def token_required(f):
    """Decorator to verify JWT token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        payload = AuthService.verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Get user from database
        current_user = User.query.get(payload['user_id'])
        if not current_user or not current_user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated_function


def role_required(allowed_roles):
    """Decorator to check user role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user.role not in allowed_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator


# ============================================
# HEALTH & STATUS ENDPOINTS
# ============================================

@health_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        db_status = 'connected'
    except Exception as e:
        db_status = 'disconnected'
        logger.error(f"Database health check failed: {str(e)}")
    
    return jsonify({
        'status': 'healthy',
        'service': 'Data Access Service',
        'database': db_status,
        'version': '1.0.0'
    }), 200


@health_bp.route('/status', methods=['GET'])
def service_status():
    """Detailed service status"""
    try:
        # Get resource counts
        patient_count = FHIRResource.query.filter_by(resource_type='Patient').count()
        observation_count = FHIRResource.query.filter_by(resource_type='Observation').count()
        condition_count = FHIRResource.query.filter_by(resource_type='Condition').count()
        user_count = User.query.count()
        
        return jsonify({
            'status': 'operational',
            'database': {
                'patients': patient_count,
                'observations': observation_count,
                'conditions': condition_count,
                'users': user_count
            }
        }), 200
    except Exception as e:
        logger.error(f"Status check failed: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Authenticate user
        result = AuthService.authenticate(username, password)
        
        if result:
            # Log successful login
            AuditService.log_access(
                user_id=result['user']['id'],
                action='LOGIN',
                status_code=200
            )
            
            return jsonify({
                'message': 'Login successful',
                'tokens': result['tokens'],
                'user': result['user']
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        required_fields = ['username', 'email', 'password', 'role']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Register user
        result = AuthService.register_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            role=data['role'],
            department=data.get('department')
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'user': result
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500


@auth_bp.route('/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    """Verify if token is valid"""
    return jsonify({
        'valid': True,
        'user': {
            'user_id': current_user.id,
            'username': current_user.username,
            'role': current_user.role
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    """Logout user and blacklist token"""
    try:
        token = request.headers['Authorization'].split(' ')[1]
        AuthService.revoke_token(token, current_user.id)
        
        # Log logout
        AuditService.log_access(
            user_id=current_user.id,
            action='LOGOUT',
            status_code=200
        )
        
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500


# ============================================
# FHIR PATIENT ENDPOINTS
# ============================================

@fhir_bp.route('/Patient', methods=['GET'])
@token_required
@role_required(['ADMIN', 'DOCTOR', 'NURSE', 'VIEWER'])
def search_patients(current_user):
    """Search for patients with filters"""
    try:
        # Get query parameters
        name = request.args.get('name')
        gender = request.args.get('gender')
        birthdate = request.args.get('birthdate')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        # Start with base query
        query = FHIRResource.query.filter_by(resource_type='Patient')
        
        # Apply simple filters
        if gender:
            # Filter using JSONB
            query = query.filter(
                FHIRResource.data['gender'].astext == gender
            )
        
        if birthdate:
            query = query.filter(
                FHIRResource.data['birthDate'].astext == birthdate
            )
        
        # Count total
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        resources = query.offset(offset).limit(per_page).all()
        
        # Extract data and filter by name in Python if needed
        result_data = []
        for resource in resources:
            data = resource.data
            
            # Apply name filter in Python
            if name:
                patient_names = data.get('name', [])
                name_match = False
                for name_obj in patient_names:
                    given = ' '.join(name_obj.get('given', []))
                    family = name_obj.get('family', '')
                    full_name = f"{given} {family}".lower()
                    if name.lower() in full_name:
                        name_match = True
                        break
                if not name_match:
                    continue
            
            result_data.append(data)
        
        # Log the access
        AuditService.log_access(
            user_id=current_user.id,
            action='SEARCH',
            resource_type='Patient',
            status_code=200
        )
        
        return jsonify({
            'resources': result_data,
            'total': len(result_data) if name else total,
            'page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        logger.error(f"Patient search failed: {str(e)}")
        import traceback
        traceback.print_exc()
        
        AuditService.log_access(
            user_id=current_user.id,
            action='SEARCH',
            resource_type='Patient',
            status_code=500,
            error_message=str(e)
        )
        
        return jsonify({'error': 'Search failed', 'details': str(e)}), 500


@fhir_bp.route('/Patient/<string:patient_id>', methods=['GET'])
@token_required
@role_required(['ADMIN', 'DOCTOR', 'NURSE', 'VIEWER', 'PATIENT'])
def get_patient(current_user, patient_id):
    """Get specific patient by ID"""
    try:
        resource = FHIRResource.query.filter_by(
            resource_type='Patient',
            fhir_id=patient_id
        ).first()
        
        if not resource:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Log the access
        AuditService.log_access(
            user_id=current_user.id,
            action='READ',
            resource_type='Patient',
            fhir_id=patient_id,
            patient_fhir_id=patient_id,
            status_code=200
        )
        
        return jsonify(resource.data), 200
        
    except Exception as e:
        logger.error(f"Get patient failed: {str(e)}")
        return jsonify({'error': 'Failed to retrieve patient'}), 500


# ============================================
# FHIR OBSERVATION ENDPOINTS
# ============================================

@fhir_bp.route('/Observation', methods=['GET'])
@token_required
@role_required(['ADMIN', 'DOCTOR', 'NURSE', 'VIEWER'])
def search_observations(current_user):
    """Search for observations with filters"""
    try:
        patient = request.args.get('patient')
        code = request.args.get('code')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        # Build query
        query = FHIRResource.query.filter_by(resource_type='Observation')
        
        # Filter by patient if provided
        if patient:
            query = query.filter(FHIRResource.patient_fhir_id == patient)
        
        # Count and paginate
        total = query.count()
        offset = (page - 1) * per_page
        resources = query.offset(offset).limit(per_page).all()
        
        # Extract data and filter by code if needed
        result_data = []
        for resource in resources:
            data = resource.data
            
            # Filter by code in Python
            if code:
                code_data = data.get('code', {})
                code_text = code_data.get('text', '')
                if code.lower() not in code_text.lower():
                    continue
            
            result_data.append(data)
        
        # Log the access
        AuditService.log_access(
            user_id=current_user.id,
            action='SEARCH',
            resource_type='Observation',
            patient_fhir_id=patient,
            status_code=200
        )
        
        return jsonify({
            'resources': result_data,
            'total': len(result_data) if code else total,
            'page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        logger.error(f"Observation search failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Search failed', 'details': str(e)}), 500


@fhir_bp.route('/Observation/<string:observation_id>', methods=['GET'])
@token_required
@role_required(['ADMIN', 'DOCTOR', 'NURSE', 'VIEWER'])
def get_observation(current_user, observation_id):
    """Get specific observation by ID"""
    try:
        resource = FHIRResource.query.filter_by(
            resource_type='Observation',
            fhir_id=observation_id
        ).first()
        
        if not resource:
            return jsonify({'error': 'Observation not found'}), 404
        
        # Log the access
        AuditService.log_access(
            user_id=current_user.id,
            action='READ',
            resource_type='Observation',
            fhir_id=observation_id,
            patient_fhir_id=resource.patient_fhir_id,
            status_code=200
        )
        
        return jsonify(resource.data), 200
        
    except Exception as e:
        logger.error(f"Get observation failed: {str(e)}")
        return jsonify({'error': 'Failed to retrieve observation'}), 500


# ============================================
# FHIR CONDITION ENDPOINTS
# ============================================

@fhir_bp.route('/Condition', methods=['GET'])
@token_required
@role_required(['ADMIN', 'DOCTOR', 'NURSE', 'VIEWER'])
def search_conditions(current_user):
    """Search for conditions with filters"""
    try:
        patient = request.args.get('patient')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        # Build query
        query = FHIRResource.query.filter_by(resource_type='Condition')
        
        # Filter by patient
        if patient:
            query = query.filter(FHIRResource.patient_fhir_id == patient)
        
        # Count and paginate
        total = query.count()
        offset = (page - 1) * per_page
        resources = query.offset(offset).limit(per_page).all()
        
        # Extract data
        result_data = [resource.data for resource in resources]
        
        # Log the access
        AuditService.log_access(
            user_id=current_user.id,
            action='SEARCH',
            resource_type='Condition',
            patient_fhir_id=patient,
            status_code=200
        )
        
        return jsonify({
            'resources': result_data,
            'total': total,
            'page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        logger.error(f"Condition search failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Search failed', 'details': str(e)}), 500


@fhir_bp.route('/Condition/<string:condition_id>', methods=['GET'])
@token_required
@role_required(['ADMIN', 'DOCTOR', 'NURSE', 'VIEWER'])
def get_condition(current_user, condition_id):
    """Get specific condition by ID"""
    try:
        resource = FHIRResource.query.filter_by(
            resource_type='Condition',
            fhir_id=condition_id
        ).first()
        
        if not resource:
            return jsonify({'error': 'Condition not found'}), 404
        
        # Log the access
        AuditService.log_access(
            user_id=current_user.id,
            action='READ',
            resource_type='Condition',
            fhir_id=condition_id,
            patient_fhir_id=resource.patient_fhir_id,
            status_code=200
        )
        
        return jsonify(resource.data), 200
        
    except Exception as e:
        logger.error(f"Get condition failed: {str(e)}")
        return jsonify({'error': 'Failed to retrieve condition'}), 500


# ============================================
# FHIR BUNDLE ENDPOINT
# ============================================

@fhir_bp.route('/Patient/<string:patient_id>/Bundle', methods=['GET'])
@token_required
@role_required(['ADMIN', 'DOCTOR', 'NURSE', 'VIEWER'])
def get_patient_bundle(current_user, patient_id):
    """Get complete patient bundle with all related resources"""
    try:
        bundle = FHIRService.get_patient_bundle(patient_id)
        
        if not bundle:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Log the access
        AuditService.log_access(
            user_id=current_user.id,
            action='READ',
            resource_type='Bundle',
            patient_fhir_id=patient_id,
            status_code=200
        )
        
        return jsonify(bundle), 200
        
    except Exception as e:
        logger.error(f"Get patient bundle failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to retrieve patient bundle'}), 500


# ============================================
# ADMIN ENDPOINTS
# ============================================

@admin_bp.route('/audit-logs', methods=['GET'])
@token_required
@role_required(['ADMIN'])
def get_audit_logs(current_user):
    """Get audit logs (admin only)"""
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        logs = AccessLog.query.order_by(
            AccessLog.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        result = []
        for log in logs:
            result.append({
                'id': log.id,
                'user_id': log.user_id,
                'action': log.action,
                'resource_type': log.resource_type,
                'fhir_id': log.fhir_id,
                'patient_fhir_id': log.patient_fhir_id,
                'status_code': log.status_code,
                'ip_address': log.ip_address,
                'created_at': log.created_at.isoformat() if log.created_at else None
            })
        
        return jsonify({
            'logs': result,
            'total': len(result)
        }), 200
        
    except Exception as e:
        logger.error(f"Get audit logs failed: {str(e)}")
        return jsonify({'error': 'Failed to retrieve audit logs'}), 500


@admin_bp.route('/user-activity/<int:user_id>', methods=['GET'])
@token_required
@role_required(['ADMIN'])
def get_user_activity(current_user, user_id):
    """Get activity logs for specific user (admin only)"""
    try:
        limit = int(request.args.get('limit', 50))
        
        logs = AccessLog.query.filter_by(
            user_id=user_id
        ).order_by(
            AccessLog.created_at.desc()
        ).limit(limit).all()
        
        result = []
        for log in logs:
            result.append({
                'id': log.id,
                'action': log.action,
                'resource_type': log.resource_type,
                'fhir_id': log.fhir_id,
                'status_code': log.status_code,
                'created_at': log.created_at.isoformat() if log.created_at else None
            })
        
        return jsonify({
            'user_id': user_id,
            'activity': result,
            'total': len(result)
        }), 200
        
    except Exception as e:
        logger.error(f"Get user activity failed: {str(e)}")
        return jsonify({'error': 'Failed to retrieve user activity'}), 500
