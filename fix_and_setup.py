
"""
Fix database and setup all data
Updated for extended FHIR service with new resource types:
- Patient, Observation, Condition, MedicationStatement, Procedure, Encounter
"""
from app import create_app, db
from models import User, FHIRResource, AccessLog, TokenBlacklist, PermissionMatrix
from werkzeug.security import generate_password_hash
from datetime import datetime
import json

app = create_app()

def setup_database():
    with app.app_context():
        print("\n[*] Setting up database...\n")
        
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
            User(username='doctor2', email='doctor2@emr.com', 
                 password_hash=generate_password_hash('doctor123'), 
                 role='DOCTOR', department='Neurology', is_active=True),
            User(username='nurse1', email='nurse1@emr.com', 
                 password_hash=generate_password_hash('nurse123'), 
                 role='NURSE', department='Emergency', is_active=True),
            User(username='nurse2', email='nurse2@emr.com', 
                 password_hash=generate_password_hash('nurse123'), 
                 role='NURSE', department='ICU', is_active=True),
            # Link patient users to patient resource IDs
            User(username='patient1', email='patient1@emr.com', 
                 password_hash=generate_password_hash('patient123'), 
                 role='PATIENT', department=None, is_active=True,
                 fhir_patient_id='pat-001'),
            User(username='patient2', email='patient2@emr.com', 
                 password_hash=generate_password_hash('patient123'), 
                 role='PATIENT', department=None, is_active=True,
                 fhir_patient_id='pat-002'),
            User(username='viewer1', email='viewer1@emr.com', 
                 password_hash=generate_password_hash('viewer123'), 
                 role='VIEWER', department='Research', is_active=True),
        ]
        
        for user in users:
            db.session.add(user)
            print(f"   [OK] Created: {user.username} ({user.role})")
        
        db.session.commit()
        
        # Create permissions
        print("\n4. Creating permissions...")
        permissions = [
            # Admin - full access to all resources and actions
            PermissionMatrix(role='ADMIN', resource_type='*', action='*', can_access_own_data_only=False),
            PermissionMatrix(role='ADMIN', resource_type='Bundle', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='ADMIN', resource_type='Bundle', action='WRITE', can_access_own_data_only=False),
            
            # Doctor - read all and create resources
            PermissionMatrix(role='DOCTOR', resource_type='Patient', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Observation', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Observation', action='CREATE', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Condition', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Condition', action='CREATE', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='MedicationStatement', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='MedicationStatement', action='CREATE', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Procedure', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Procedure', action='CREATE', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Encounter', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Encounter', action='CREATE', can_access_own_data_only=False),
            PermissionMatrix(role='DOCTOR', resource_type='Bundle', action='READ', can_access_own_data_only=False),
            
            # Nurse - read all and basic create
            PermissionMatrix(role='NURSE', resource_type='Patient', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='NURSE', resource_type='Observation', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='NURSE', resource_type='Observation', action='CREATE', can_access_own_data_only=False),
            PermissionMatrix(role='NURSE', resource_type='Condition', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='NURSE', resource_type='MedicationStatement', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='NURSE', resource_type='Procedure', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='NURSE', resource_type='Encounter', action='READ', can_access_own_data_only=False),
            
            # Patient - own data only
            PermissionMatrix(role='PATIENT', resource_type='Patient', action='READ', can_access_own_data_only=True),
            PermissionMatrix(role='PATIENT', resource_type='Observation', action='READ', can_access_own_data_only=True),
            PermissionMatrix(role='PATIENT', resource_type='Condition', action='READ', can_access_own_data_only=True),
            PermissionMatrix(role='PATIENT', resource_type='MedicationStatement', action='READ', can_access_own_data_only=True),
            PermissionMatrix(role='PATIENT', resource_type='Procedure', action='READ', can_access_own_data_only=True),
            PermissionMatrix(role='PATIENT', resource_type='Encounter', action='READ', can_access_own_data_only=True),
            PermissionMatrix(role='PATIENT', resource_type='Bundle', action='READ', can_access_own_data_only=True),
            
            # Viewer - read-only access
            PermissionMatrix(role='VIEWER', resource_type='Patient', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='VIEWER', resource_type='Observation', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='VIEWER', resource_type='Condition', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='VIEWER', resource_type='MedicationStatement', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='VIEWER', resource_type='Procedure', action='READ', can_access_own_data_only=False),
            PermissionMatrix(role='VIEWER', resource_type='Encounter', action='READ', can_access_own_data_only=False),
        ]
        
        for perm in permissions:
            db.session.add(perm)
        
        db.session.commit()
        print("   [OK] Permissions created")
        
        # Add FHIR data
        print("\n5. Adding FHIR sample data...")
        
        # Add patients
        patients = [
            {"resourceType": "Patient", "id": "pat-001", "name": [{"given": ["John"], "family": "Doe"}], 
             "gender": "male", "birthDate": "1980-01-15", "contact": [{"telecom": [{"system": "email", "value": "john@example.com"}]}]},
            {"resourceType": "Patient", "id": "pat-002", "name": [{"given": ["Jane"], "family": "Smith"}], 
             "gender": "female", "birthDate": "1992-05-20", "contact": [{"telecom": [{"system": "email", "value": "jane@example.com"}]}]},
            {"resourceType": "Patient", "id": "pat-003", "name": [{"given": ["Raj"], "family": "Kumar"}], 
             "gender": "male", "birthDate": "1975-11-03", "contact": [{"telecom": [{"system": "email", "value": "raj@example.com"}]}]},
        ]
        
        for pat in patients:
            resource = FHIRResource(
                fhir_id=pat['id'],
                resource_type='Patient',
                patient_fhir_id=pat['id'],
                data=pat,
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            name = f"{pat['name'][0]['given'][0]} {pat['name'][0]['family']}"
            print(f"   [OK] Patient: {name}")
        
        # Add observations
        observations = [
            {"resourceType": "Observation", "id": "obs-001", "subject": {"reference": "Patient/pat-001"},
             "code": {"text": "Blood Pressure"}, "valueString": "120/80 mmHg", "status": "final", "effectiveDateTime": "2025-12-23"},
            {"resourceType": "Observation", "id": "obs-002", "subject": {"reference": "Patient/pat-001"},
             "code": {"text": "Heart Rate"}, "valueQuantity": {"value": 72, "unit": "bpm"}, "status": "final", "effectiveDateTime": "2025-12-23"},
            {"resourceType": "Observation", "id": "obs-003", "subject": {"reference": "Patient/pat-002"},
             "code": {"text": "Temperature"}, "valueQuantity": {"value": 36.8, "unit": "C"}, "status": "final", "effectiveDateTime": "2025-12-23"},
            {"resourceType": "Observation", "id": "obs-004", "subject": {"reference": "Patient/pat-003"},
             "code": {"text": "Blood Glucose"}, "valueQuantity": {"value": 110, "unit": "mg/dL"}, "status": "final", "effectiveDateTime": "2025-12-23"},
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
            print(f"   [OK] Observation: {obs['code']['text']}")
        
        # Add conditions
        conditions = [
            {"resourceType": "Condition", "id": "cond-001", "subject": {"reference": "Patient/pat-001"},
             "code": {"text": "Hypertension"}, "clinicalStatus": {"coding": [{"code": "active"}]}, "recordedDate": "2025-12-23"},
            {"resourceType": "Condition", "id": "cond-002", "subject": {"reference": "Patient/pat-002"},
             "code": {"text": "Type 2 Diabetes"}, "clinicalStatus": {"coding": [{"code": "active"}]}, "recordedDate": "2025-12-23"},
            {"resourceType": "Condition", "id": "cond-003", "subject": {"reference": "Patient/pat-003"},
             "code": {"text": "Asthma"}, "clinicalStatus": {"coding": [{"code": "remission"}]}, "recordedDate": "2025-12-23"},
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
            print(f"   [OK] Condition: {cond['code']['text']}")
        
        # Add medication statements (NEW)
        medications = [
            {"resourceType": "MedicationStatement", "id": "med-001", "subject": {"reference": "Patient/pat-001"},
             "medicationCodeableConcept": {"text": "Lisinopril 10mg"}, "status": "active", "effectiveDateTime": "2025-12-23"},
            {"resourceType": "MedicationStatement", "id": "med-002", "subject": {"reference": "Patient/pat-002"},
             "medicationCodeableConcept": {"text": "Metformin 500mg"}, "status": "active", "effectiveDateTime": "2025-12-23"},
            {"resourceType": "MedicationStatement", "id": "med-003", "subject": {"reference": "Patient/pat-001"},
             "medicationCodeableConcept": {"text": "Atorvastatin 20mg"}, "status": "active", "effectiveDateTime": "2025-12-23"},
        ]
        
        for med in medications:
            resource = FHIRResource(
                fhir_id=med['id'],
                resource_type='MedicationStatement',
                patient_fhir_id=med['subject']['reference'].split('/')[1],
                data=med,
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            print(f"   [OK] Medication: {med['medicationCodeableConcept']['text']}")
        
        # Add procedures (NEW)
        procedures = [
            {"resourceType": "Procedure", "id": "proc-001", "subject": {"reference": "Patient/pat-001"},
             "code": {"text": "Cardiac Catheterization"}, "status": "completed", "performedDateTime": "2025-12-20"},
            {"resourceType": "Procedure", "id": "proc-002", "subject": {"reference": "Patient/pat-002"},
             "code": {"text": "Glucose Tolerance Test"}, "status": "completed", "performedDateTime": "2025-12-15"},
            {"resourceType": "Procedure", "id": "proc-003", "subject": {"reference": "Patient/pat-003"},
             "code": {"text": "Pulmonary Function Test"}, "status": "completed", "performedDateTime": "2025-12-10"},
        ]
        
        for proc in procedures:
            resource = FHIRResource(
                fhir_id=proc['id'],
                resource_type='Procedure',
                patient_fhir_id=proc['subject']['reference'].split('/')[1],
                data=proc,
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            print(f"   [OK] Procedure: {proc['code']['text']}")
        
        # Add encounters (NEW)
        encounters = [
            {"resourceType": "Encounter", "id": "enc-001", "subject": {"reference": "Patient/pat-001"},
             "status": "finished", "class": {"code": "AMB"}, "type": [{"text": "Cardiology Consultation"}], "period": {"start": "2025-12-23T09:00:00", "end": "2025-12-23T10:00:00"}},
            {"resourceType": "Encounter", "id": "enc-002", "subject": {"reference": "Patient/pat-002"},
             "status": "finished", "class": {"code": "AMB"}, "type": [{"text": "Endocrinology Consultation"}], "period": {"start": "2025-12-23T10:30:00", "end": "2025-12-23T11:30:00"}},
            {"resourceType": "Encounter", "id": "enc-003", "subject": {"reference": "Patient/pat-001"},
             "status": "in-progress", "class": {"code": "IMP"}, "type": [{"text": "Hospital Admission"}], "period": {"start": "2025-12-22T14:00:00"}},
        ]
        
        for enc in encounters:
            resource = FHIRResource(
                fhir_id=enc['id'],
                resource_type='Encounter',
                patient_fhir_id=enc['subject']['reference'].split('/')[1],
                data=enc,
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            print(f"   [OK] Encounter: {enc['type'][0]['text']}")
        
        db.session.commit()
        
        print("\n" + "="*60)
        print("[SUCCESS] DATABASE SETUP COMPLETE!")
        print("="*60)
        print(f"\n[INFO] Summary:")
        print(f"   Users: {User.query.count()}")
        print(f"   - Admin: {User.query.filter_by(role='ADMIN').count()}")
        print(f"   - Doctors: {User.query.filter_by(role='DOCTOR').count()}")
        print(f"   - Nurses: {User.query.filter_by(role='NURSE').count()}")
        print(f"   - Patients: {User.query.filter_by(role='PATIENT').count()}")
        print(f"   - Viewers: {User.query.filter_by(role='VIEWER').count()}")
        print(f"\n   FHIR Resources:")
        print(f"   - Patients: {FHIRResource.query.filter_by(resource_type='Patient').count()}")
        print(f"   - Observations: {FHIRResource.query.filter_by(resource_type='Observation').count()}")
        print(f"   - Conditions: {FHIRResource.query.filter_by(resource_type='Condition').count()}")
        print(f"   - Medications: {FHIRResource.query.filter_by(resource_type='MedicationStatement').count()}")
        print(f"   - Procedures: {FHIRResource.query.filter_by(resource_type='Procedure').count()}")
        print(f"   - Encounters: {FHIRResource.query.filter_by(resource_type='Encounter').count()}")
        print(f"   - Total Resources: {FHIRResource.query.count()}")
        print(f"\n   Permissions: {PermissionMatrix.query.count()}")
        print("\n" + "="*60)
        print("[OK] TEST CREDENTIALS:")
        print("="*60)
        print("\n   ADMIN:")
        print("      Username: admin")
        print("      Password: admin123")
        print("\n   DOCTOR:")
        print("      Username: doctor1")
        print("      Password: doctor123")
        print("\n   PATIENT:")
        print("      Username: patient1")
        print("      Password: patient123")
        print("      (Linked to Patient ID: pat-001)")
        print("\n" + "="*60)
        print("[READY] Ready to start server: python app.py")
        print("="*60 + "\n")

if __name__ == '__main__':
    setup_database()