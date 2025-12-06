# Database Initialization and Seed Data
from app import create_app, db
from models import User, PermissionMatrix
from auth_service import AuthService
import logging

logger = logging.getLogger(__name__)


def seed_database():
    """Seed initial data for the database"""
    
    app = create_app()
    
    with app.app_context():
        # Clear existing data (only in development)
        if app.config['DEBUG']:
            logger.info("Clearing existing data...")
            db.drop_all()
            db.create_all()
        
        # Create default users
        users_data = [
            {
                'username': 'admin',
                'email': 'admin@emr.com',
                'password': 'admin123',
                'role': 'ADMIN',
                'department': 'Administration',
                'license_number': 'ADM001'
            },
            {
                'username': 'doctor1',
                'email': 'doctor1@emr.com',
                'password': 'doctor123',
                'role': 'DOCTOR',
                'department': 'Cardiology',
                'license_number': 'MED001'
            },
            {
                'username': 'nurse1',
                'email': 'nurse1@emr.com',
                'password': 'nurse123',
                'role': 'NURSE',
                'department': 'General Ward',
                'license_number': 'NUR001'
            },
            {
                'username': 'patient1',
                'email': 'patient1@emr.com',
                'password': 'patient123',
                'role': 'PATIENT',
                'department': 'Patients'
            },
            {
                'username': 'viewer1',
                'email': 'viewer1@emr.com',
                'password': 'viewer123',
                'role': 'VIEWER',
                'department': 'Support'
            }
        ]
        
        logger.info("Creating default users...")
        for user_data in users_data:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=AuthService.hash_password(user_data['password']),
                role=user_data['role'],
                department=user_data['department'],
                license_number=user_data.get('license_number'),
                is_active=True
            )
            db.session.add(user)
            logger.info(f"Created user: {user.username} ({user.role})")
        
        db.session.commit()
        
        # Create permission matrix
        permissions_data = [
            # ADMIN - Full access
            {'role': 'ADMIN', 'resource_type': '*', 'action': '*', 'own_data_only': False},
            
            # DOCTOR - Read all, limited write
            {'role': 'DOCTOR', 'resource_type': 'Patient', 'action': 'READ', 'own_data_only': False},
            {'role': 'DOCTOR', 'resource_type': 'Observation', 'action': 'READ', 'own_data_only': False},
            {'role': 'DOCTOR', 'resource_type': 'Condition', 'action': 'READ', 'own_data_only': False},
            {'role': 'DOCTOR', 'resource_type': 'Medication', 'action': 'READ', 'own_data_only': False},
            {'role': 'DOCTOR', 'resource_type': 'Bundle', 'action': 'READ', 'own_data_only': False},
            
            # NURSE - Read patient data
            {'role': 'NURSE', 'resource_type': 'Patient', 'action': 'READ', 'own_data_only': False},
            {'role': 'NURSE', 'resource_type': 'Observation', 'action': 'READ', 'own_data_only': False},
            
            # PATIENT - Read own data only
            {'role': 'PATIENT', 'resource_type': 'Patient', 'action': 'READ', 'own_data_only': True},
            {'role': 'PATIENT', 'resource_type': 'Observation', 'action': 'READ', 'own_data_only': True},
            {'role': 'PATIENT', 'resource_type': 'Condition', 'action': 'READ', 'own_data_only': True},
            
            # VIEWER - Read-only access
            {'role': 'VIEWER', 'resource_type': 'Patient', 'action': 'READ', 'own_data_only': False},
            {'role': 'VIEWER', 'resource_type': 'Observation', 'action': 'READ', 'own_data_only': False},
        ]
        
        logger.info("Creating permission matrix...")
        for perm_data in permissions_data:
            perm = PermissionMatrix(
                role=perm_data['role'],
                resource_type=perm_data['resource_type'],
                action=perm_data['action'],
                can_access_own_data_only=perm_data['own_data_only']
            )
            db.session.add(perm)
            logger.info(f"Created permission: {perm.role}:{perm.resource_type}:{perm.action}")
        
        db.session.commit()
        
        logger.info("Database seeding completed successfully!")


if __name__ == '__main__':
    seed_database()