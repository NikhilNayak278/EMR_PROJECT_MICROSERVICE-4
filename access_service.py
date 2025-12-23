"""
Access Control Service - Role-based permission checking
"""
import logging
from models import PermissionMatrix, db

logger = logging.getLogger(__name__)


class AccessService:
    """Handle granular permission checking for resources and actions"""
    
    @staticmethod
    def has_permission(user_role, resource_type, action):
        """
        Check if a user role has permission to perform an action on a resource type.
        
        Args:
            user_role: User's role (ADMIN, DOCTOR, NURSE, PATIENT, VIEWER)
            resource_type: Resource being accessed (Patient, Observation, etc.)
            action: Action being performed (READ, CREATE, UPDATE, DELETE)
            
        Returns:
            True if permission granted, False otherwise
        """
        try:
            # Admin can access everything
            if user_role == 'ADMIN':
                return True
            
            # Check permission matrix
            perm = PermissionMatrix.query.filter(
                ((PermissionMatrix.role == user_role) |
                 (PermissionMatrix.role == '*')),
                ((PermissionMatrix.resource_type == resource_type) |
                 (PermissionMatrix.resource_type == '*')),
                ((PermissionMatrix.action == action) |
                 (PermissionMatrix.action == '*'))
            ).first()
            
            if perm:
                logger.info(f"Permission granted: {user_role} -> {resource_type}:{action}")
                return True
            
            logger.warning(f"Permission denied: {user_role} -> {resource_type}:{action}")
            return False
            
        except Exception as e:
            logger.error(f"Error checking permission: {str(e)}")
            return False
    
    @staticmethod
    def get_user_permissions(user_role):
        """Get all permissions for a specific user role"""
        try:
            perms = PermissionMatrix.query.filter_by(role=user_role).all()
            return [p.to_dict() for p in perms]
        except Exception as e:
            logger.error(f"Error getting permissions: {str(e)}")
            return []
    
    @staticmethod
    def add_permission(role, resource_type, action, can_access_own_data_only=False):
        """Add a new permission to the matrix"""
        try:
            # Check if permission already exists
            existing = PermissionMatrix.query.filter_by(
                role=role,
                resource_type=resource_type,
                action=action
            ).first()
            
            if existing:
                logger.warning(f"Permission already exists: {role}:{resource_type}:{action}")
                return False
            
            # Create new permission
            perm = PermissionMatrix(
                role=role,
                resource_type=resource_type,
                action=action,
                can_access_own_data_only=can_access_own_data_only
            )
            db.session.add(perm)
            db.session.commit()
            logger.info(f"Permission added: {role}:{resource_type}:{action}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding permission: {str(e)}")
            db.session.rollback()
            return False
    
    @staticmethod
    def remove_permission(role, resource_type, action):
        """Remove a permission from the matrix"""
        try:
            PermissionMatrix.query.filter_by(
                role=role,
                resource_type=resource_type,
                action=action
            ).delete()
            db.session.commit()
            logger.info(f"Permission removed: {role}:{resource_type}:{action}")
            return True
        except Exception as e:
            logger.error(f"Error removing permission: {str(e)}")
            db.session.rollback()
            return False
