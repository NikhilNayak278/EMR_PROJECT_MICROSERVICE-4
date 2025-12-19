# """
# Fix database and setup all data
# """
# from app import create_app, db
# from models import User, FHIRResource, AccessLog, TokenBlacklist, PermissionMatrix
# from werkzeug.security import generate_password_hash
# from datetime import datetime
# import json

# app = create_app()

# def setup_database():
#     with app.app_context():
#         print("\n🔄 Setting up database...\n")
        
#         # Drop and recreate
#         print("1. Dropping old tables...")
#         db.drop_all()
        
#         print("2. Creating new tables...")
#         db.create_all()
        
#         # Create users
#         print("\n3. Creating users...")
#         users = [
#             User(username='admin', email='admin@emr.com', 
#                  password_hash=generate_password_hash('admin123'), 
#                  role='ADMIN', department='Administration', is_active=True),
#             User(username='doctor1', email='doctor1@emr.com', 
#                  password_hash=generate_password_hash('doctor123'), 
#                  role='DOCTOR', department='Cardiology', is_active=True),
#             User(username='nurse1', email='nurse1@emr.com', 
#                  password_hash=generate_password_hash('nurse123'), 
#                  role='NURSE', department='Emergency', is_active=True),
#             User(username='patient1', email='patient1@emr.com', 
#                  password_hash=generate_password_hash('patient123'), 
#                  role='PATIENT', department=None, is_active=True),
#             User(username='viewer1', email='viewer1@emr.com', 
#                  password_hash=generate_password_hash('viewer123'), 
#                  role='VIEWER', department='Research', is_active=True),
#         ]
        
#         for user in users:
#             db.session.add(user)
#             print(f"   ✅ Created: {user.username} ({user.role})")
        
#         db.session.commit()
        
#         # Create permissions
#         print("\n4. Creating permissions...")
#         permissions = [
#             # Admin - full access
#             PermissionMatrix(role='ADMIN', resource_type='Patient', action='READ', can_access_own_data_only=False),
#             PermissionMatrix(role='ADMIN', resource_type='Observation', action='READ', can_access_own_data_only=False),
#             PermissionMatrix(role='ADMIN', resource_type='Condition', action='READ', can_access_own_data_only=False),
            
#             # Doctor - read all
#             PermissionMatrix(role='DOCTOR', resource_type='Patient', action='READ', can_access_own_data_only=False),
#             PermissionMatrix(role='DOCTOR', resource_type='Observation', action='READ', can_access_own_data_only=False),
#             PermissionMatrix(role='DOCTOR', resource_type='Condition', action='READ', can_access_own_data_only=False),
            
#             # Nurse - limited
#             PermissionMatrix(role='NURSE', resource_type='Patient', action='READ', can_access_own_data_only=False),
            
#             # Patient - own data only
#             PermissionMatrix(role='PATIENT', resource_type='Patient', action='READ', can_access_own_data_only=True),
#             PermissionMatrix(role='PATIENT', resource_type='Observation', action='READ', can_access_own_data_only=True),
#         ]
        
#         for perm in permissions:
#             db.session.add(perm)
        
#         db.session.commit()
#         print("   ✅ Permissions created")
        
#         # Add FHIR data
#         print("\n5. Adding FHIR sample data...")
        
#         patients = [
#             {"resourceType": "Patient", "id": "pat-001", "name": [{"given": ["John"], "family": "Doe"}], 
#              "gender": "male", "birthDate": "1980-01-15"},
#             {"resourceType": "Patient", "id": "pat-002", "name": [{"given": ["Jane"], "family": "Smith"}], 
#              "gender": "female", "birthDate": "1992-05-20"},
#             {"resourceType": "Patient", "id": "pat-003", "name": [{"given": ["Raj"], "family": "Kumar"}], 
#              "gender": "male", "birthDate": "1975-11-03"},
#         ]
        
#         for pat in patients:
#             resource = FHIRResource(
#                 fhir_id=pat['id'],
#                 resource_type='Patient',
#                 patient_fhir_id=pat['id'],
#                 data=pat,  # JSONB handles dict automatically
#                 created_at=datetime.utcnow()
#             )
#             db.session.add(resource)
#             name = f"{pat['name'][0]['given'][0]} {pat['name'][0]['family']}"
#             print(f"   ✅ Patient: {name}")
        
#         observations = [
#             {"resourceType": "Observation", "id": "obs-001", "subject": {"reference": "Patient/pat-001"},
#              "code": {"text": "Blood Pressure"}, "valueString": "120/80 mmHg", "status": "final"},
#             {"resourceType": "Observation", "id": "obs-002", "subject": {"reference": "Patient/pat-001"},
#              "code": {"text": "Heart Rate"}, "valueQuantity": {"value": 72, "unit": "bpm"}, "status": "final"},
#         ]
        
#         for obs in observations:
#             resource = FHIRResource(
#                 fhir_id=obs['id'],
#                 resource_type='Observation',
#                 patient_fhir_id=obs['subject']['reference'].split('/')[1],
#                 data=obs,
#                 created_at=datetime.utcnow()
#             )
#             db.session.add(resource)
#             print(f"   ✅ Observation: {obs['code']['text']}")
        
#         conditions = [
#             {"resourceType": "Condition", "id": "cond-001", "subject": {"reference": "Patient/pat-001"},
#              "code": {"text": "Hypertension"}, "clinicalStatus": {"text": "active"}},
#         ]
        
#         for cond in conditions:
#             resource = FHIRResource(
#                 fhir_id=cond['id'],
#                 resource_type='Condition',
#                 patient_fhir_id=cond['subject']['reference'].split('/')[1],
#                 data=cond,
#                 created_at=datetime.utcnow()
#             )
#             db.session.add(resource)
#             print(f"   ✅ Condition: {cond['code']['text']}")
        
#         db.session.commit()
        
#         print("\n" + "="*50)
#         print("🎉 DATABASE SETUP COMPLETE!")
#         print("="*50)
#         print(f"\n📊 Summary:")
#         print(f"   Users: {User.query.count()}")
#         print(f"   Patients: {FHIRResource.query.filter_by(resource_type='Patient').count()}")
#         print(f"   Observations: {FHIRResource.query.filter_by(resource_type='Observation').count()}")
#         print(f"   Conditions: {FHIRResource.query.filter_by(resource_type='Condition').count()}")
#         print("\n✅ Ready to start server: python app.py\n")

# if __name__ == '__main__':
#     setup_database()

"""
Fix database and setup all data
"""
from app import create_app, db
from models import User, FHIRResource, AccessLog, TokenBlacklist, PermissionMatrix
from werkzeug.security import generate_password_hash
from datetime import datetime
import json

app = create_app()

def setup_database():
    with app.app_context():
        print("\n🔄 Setting up database...\n")
        
        # Drop and recreate
        print("1. Dropping old tables...")
        db.drop_all()
        
        print("2. Creating new tables...")
        db.create_all()
        
        # Create users
        print("\n3. Creating users...")
        users = [
            User(username='admin', email='admin@emr.com', 
                 password_hash=generate_password_hash('admin123'), 
                 role='ADMIN', department='Administration', is_active=True),
            User(username='doctor1', email='doctor1@emr.com', 
                 password_hash=generate_password_hash('doctor123'), 
                 role='DOCTOR', department='Cardiology', is_active=True),
            User(username='nurse1', email='nurse1@emr.com', 
                 password_hash=generate_password_hash('nurse123'), 
                 role='NURSE', department='Emergency', is_active=True),
            # UPDATED: Link patient user to patient resource ID
            User(username='patient1', email='patient1@emr.com', 
                 password_hash=generate_password_hash('patient123'), 
                 role='PATIENT', department=None, is_active=True,
                 fhir_patient_id='pat-001'), 
            User(username='viewer1', email='viewer1@emr.com', 
                 password_hash=generate_password_hash('viewer123'), 
                 role='VIEWER', department='Research', is_active=True),
        ]
        
        for user in users:
            db.session.add(user)
            print(f"   ✅ Created: {user.username} ({user.role})")
        
        db.session.commit()
        
        # Create permissions
        print("\n4. Creating permissions...")
        permissions = [
            # Admin - full access
            PermissionMatrix(role='ADMIN', resource_type='Patient', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='ADMIN', resource_type='Observation', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='ADMIN', resource_type='Condition', action='READ', can_access_own_data_only=False),
            
            # Doctor - read all
            PermissionMatrix(role='DOCTOR', resource_type='Patient', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Observation', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Condition', action='READ', can_access_own_data_only=False),
            
            # Nurse - limited
            PermissionMatrix(role='NURSE', resource_type='Patient', action='READ', can_access_own_data_only=False),
            
            # Patient - own data only
            PermissionMatrix(role='PATIENT', resource_type='Patient', action='READ', can_access_own_data_only=True),
            PermissionMatrix(role='PATIENT', resource_type='Observation', action='READ', can_access_own_data_only=True),
        ]
        
        for perm in permissions:
            db.session.add(perm)
        
        db.session.commit()
        print("   ✅ Permissions created")
        
        # Add FHIR data
        print("\n5. Adding FHIR sample data...")
        
        patients = [
            {"resourceType": "Patient", "id": "pat-001", "name": [{"given": ["John"], "family": "Doe"}], 
             "gender": "male", "birthDate": "1980-01-15"},
            {"resourceType": "Patient", "id": "pat-002", "name": [{"given": ["Jane"], "family": "Smith"}], 
             "gender": "female", "birthDate": "1992-05-20"},
            {"resourceType": "Patient", "id": "pat-003", "name": [{"given": ["Raj"], "family": "Kumar"}], 
             "gender": "male", "birthDate": "1975-11-03"},
        ]
        
        for pat in patients:
            resource = FHIRResource(
                fhir_id=pat['id'],
                resource_type='Patient',
                patient_fhir_id=pat['id'],
                data=pat,  # JSONB handles dict automatically
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            name = f"{pat['name'][0]['given'][0]} {pat['name'][0]['family']}"
            print(f"   ✅ Patient: {name}")
        
        observations = [
            {"resourceType": "Observation", "id": "obs-001", "subject": {"reference": "Patient/pat-001"},
             "code": {"text": "Blood Pressure"}, "valueString": "120/80 mmHg", "status": "final"},
            {"resourceType": "Observation", "id": "obs-002", "subject": {"reference": "Patient/pat-001"},
             "code": {"text": "Heart Rate"}, "valueQuantity": {"value": 72, "unit": "bpm"}, "status": "final"},
        ]
        
        for obs in observations:
            resource = FHIRResource(
                fhir_id=obs['id'],
                resource_type='Observation',
                patient_fhir_id=obs['subject']['reference'].split('/')[1],
                data=obs,
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            print(f"   ✅ Observation: {obs['code']['text']}")
        
        conditions = [
            {"resourceType": "Condition", "id": "cond-001", "subject": {"reference": "Patient/pat-001"},
             "code": {"text": "Hypertension"}, "clinicalStatus": {"text": "active"}},
        ]
        
        for cond in conditions:
            resource = FHIRResource(
                fhir_id=cond['id'],
                resource_type='Condition',
                patient_fhir_id=cond['subject']['reference'].split('/')[1],
                data=cond,
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            print(f"   ✅ Condition: {cond['code']['text']}")
        
        db.session.commit()
        
        print("\n" + "="*50)
        print("🎉 DATABASE SETUP COMPLETE!")
        print("="*50)
        print(f"\n📊 Summary:")
        print(f"   Users: {User.query.count()}")
        print(f"   Patients: {FHIRResource.query.filter_by(resource_type='Patient').count()}")
        print(f"   Observations: {FHIRResource.query.filter_by(resource_type='Observation').count()}")
        print(f"   Conditions: {FHIRResource.query.filter_by(resource_type='Condition').count()}")
        print("\n✅ Ready to start server: python app.py\n")

if __name__ == '__main__':
    setup_database()