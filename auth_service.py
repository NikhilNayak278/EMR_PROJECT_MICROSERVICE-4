# Authentication and JWT utilities
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, TokenBlacklist, db
import logging

logger = logging.getLogger(__name__)


class AuthService:
    """Handle JWT token generation and validation"""
    
    @staticmethod
    def generate_tokens(user_id, user_role):
        """Generate access and refresh tokens"""
        try:
            now = datetime.utcnow()
            
            # Access token
            access_token_payload = {
                'user_id': user_id,
                'role': user_role,
                'type': 'access',
                'iat': now,
                'exp': now + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
            }
            
            access_token = jwt.encode(
                access_token_payload,
                current_app.config['JWT_SECRET_KEY'],
                algorithm='HS256'
            )
            
            # Refresh token
            refresh_token_payload = {
                'user_id': user_id,
                'type': 'refresh',
                'iat': now,
                'exp': now + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
            }
            
            refresh_token = jwt.encode(
                refresh_token_payload,
                current_app.config['JWT_SECRET_KEY'],
                algorithm='HS256'
            )
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            }
        except Exception as e:
            logger.error(f"Error generating tokens: {str(e)}")
            return None
    
    @staticmethod
    def verify_token(token):
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            
            # Check if token is blacklisted
            jti = payload.get('jti')
            if jti and TokenBlacklist.query.filter_by(jti=jti).first():
                return None
            
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None
    
    @staticmethod
    def hash_password(password):
        """Hash password for secure storage"""
        return generate_password_hash(password, method='pbkdf2:sha256')
    
    @staticmethod
    def verify_password(stored_hash, password):
        """Verify password against hash"""
        return check_password_hash(stored_hash, password)


def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                logger.warning("Invalid authorization header format")
                return jsonify({'error': 'Invalid authorization header'}), 401
        
        if not token:
            logger.warning("No token provided")
            return jsonify({'error': 'Token is missing'}), 401
        
        payload = AuthService.verify_token(token)
        if not payload:
            logger.warning("Token verification failed")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Attach user info to request context
        request.user_id = payload.get('user_id')
        request.user_role = payload.get('role')
        request.token_type = payload.get('type')
        
        return f(*args, **kwargs)
    
    return decorated


def role_required(*allowed_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(request, 'user_role'):
                return jsonify({'error': 'Authentication required'}), 401
            
            if request.user_role not in allowed_roles:
                logger.warning(f"Access denied for role: {request.user_role}")
                return jsonify({
                    'error': f'Access denied. Required roles: {allowed_roles}'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator


def permission_required(resource_type, action):
    """Decorator to check granular permissions"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(request, 'user_id') or not hasattr(request, 'user_role'):
                return jsonify({'error': 'Authentication required'}), 401
            
            # Get user and check permissions
            user = User.query.get(request.user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            # Admin can access everything
            if user.role == 'ADMIN':
                return f(*args, **kwargs)
            
            # Check permission matrix
            from models import PermissionMatrix
            perm = PermissionMatrix.query.filter(
                (PermissionMatrix.role == user.role) |
                (PermissionMatrix.role == '*'),
                (PermissionMatrix.resource_type == resource_type) |
                (PermissionMatrix.resource_type == '*'),
                (PermissionMatrix.action == action) |
                (PermissionMatrix.action == '*')
            ).first()
            
            if not perm:
                logger.warning(f"Permission denied for {user.role} on {resource_type}:{action}")
                return jsonify({'error': 'Permission denied'}), 403
            
            # If restricted to own data, attach flag to request
            request.own_data_only = perm.can_access_own_data_only
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator