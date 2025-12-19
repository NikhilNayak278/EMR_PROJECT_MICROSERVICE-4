"""
Authentication and JWT utilities
"""
import jwt
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, TokenBlacklist, db


logger = logging.getLogger(__name__)


class AuthService:
    """Handle JWT token generation and validation"""
   
    @staticmethod
    def authenticate(username, password):
        """Authenticate user by username and password"""
        try:
            user = User.query.filter_by(username=username).first()
           
            if not user:
                logger.warning(f"Authentication failed: User '{username}' not found")
                return None
           
            if not user.is_active:
                logger.warning(f"Authentication failed: User '{username}' is inactive")
                return None
           
            if not AuthService.verify_password(user.password_hash, password):
                logger.warning(f"Authentication failed: Invalid password for user '{username}'")
                return None
           
            logger.info(f"User '{username}' authenticated successfully")
            
            # Generate tokens
            tokens = AuthService.generate_tokens(user.id, user.role)
            
            return {
                'user': user.to_dict(),
                'tokens': tokens
            }
           
        except Exception as e:
            logger.error(f"Error authenticating user: {str(e)}")
            return None
   
    @staticmethod
    def register_user(username, email, password, role, department=None):
        """Register a new user"""
        try:
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                raise ValueError(f"Username '{username}' already exists")
           
            if User.query.filter_by(email=email).first():
                raise ValueError(f"Email '{email}' already exists")
           
            # Validate role
            valid_roles = ['ADMIN', 'DOCTOR', 'NURSE', 'PATIENT', 'VIEWER']
            if role not in valid_roles:
                raise ValueError(f"Invalid role '{role}'. Must be one of {valid_roles}")
           
            # Create user
            user = User(
                username=username,
                email=email,
                password_hash=AuthService.hash_password(password),
                role=role,
                department=department,
                is_active=True
            )
           
            db.session.add(user)
            db.session.commit()
           
            logger.info(f"User '{username}' registered successfully with role '{role}'")
            
            return user.to_dict()
           
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error registering user: {str(e)}")
            raise
   
    @staticmethod
    def generate_tokens(user_id, user_role):
        """Generate access and refresh tokens"""
        try:
            now = datetime.utcnow()
            jti = str(uuid.uuid4())
           
            # Access token
            access_token_payload = {
                'user_id': user_id,
                'role': user_role,
                'type': 'access',
                'jti': jti,
                'iat': int(now.timestamp()),
                'exp': int((now + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']).timestamp())
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
                'jti': jti,
                'iat': int(now.timestamp()),
                'exp': int((now + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']).timestamp())
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
                logger.warning(f"Token {jti} is blacklisted")
                return None
           
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None
   
    @staticmethod
    def revoke_token(token, user_id):
        """Revoke a token by adding it to blacklist"""
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
           
            jti = payload.get('jti')
            exp_timestamp = payload.get('exp')
            
            if jti and exp_timestamp:
                exp = datetime.utcfromtimestamp(exp_timestamp)
               
                blacklist_entry = TokenBlacklist(
                    jti=jti,
                    user_id=user_id,
                    expires_at=exp
                )
                db.session.add(blacklist_entry)
                db.session.commit()
                logger.info(f"Token {jti} revoked for user {user_id}")
                return True
           
            return False
           
        except Exception as e:
            logger.error(f"Error revoking token: {str(e)}")
            db.session.rollback()
            return False
   
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
       
        logger.info(f"Verifying token: {token[:20]}...")
        logger.info(f"JWT_SECRET_KEY: {current_app.config.get('JWT_SECRET_KEY', 'NOT_SET')}")
        payload = AuthService.verify_token(token)
        logger.info(f"Token verification result: {payload}")
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
                ((PermissionMatrix.role == user.role) |
                 (PermissionMatrix.role == '*')),
                ((PermissionMatrix.resource_type == resource_type) |
                 (PermissionMatrix.resource_type == '*')),
                ((PermissionMatrix.action == action) |
                 (PermissionMatrix.action == '*'))
            ).first()
           
            if not perm:
                logger.warning(f"Permission denied for {user.role} on {resource_type}:{action}")
                return jsonify({'error': 'Permission denied'}), 403
           
            # If restricted to own data, attach flag to request
            request.own_data_only = perm.can_access_own_data_only
           
            return f(*args, **kwargs)
       
        return decorated
    return decorator