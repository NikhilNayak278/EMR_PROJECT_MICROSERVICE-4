
"""
Extended FHIR Service - Handles all resource types from MS3
Supports: Patient, Observation, Condition, MedicationStatement, Procedure, Encounter
"""
import logging
from models import FHIRResource, db
from datetime import datetime


logger = logging.getLogger(__name__)



class FHIRService:
    """Enhanced FHIR resource operations with support for all MS3 resource types"""
   
    @staticmethod
    def store_fhir_bundle(bundle_dict):
        """
        Store complete FHIR bundle from MS3.
        Accepts transaction bundles and stores all resources.
        
        Args:
            bundle_dict: FHIR Bundle as dict (from MS3 output)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            entries = bundle_dict.get('entry', [])
            patient_id = None
            
            # First pass: extract and store patient to get ID
            for entry in entries:
                resource = entry.get('resource', {})
                if resource.get('resourceType') == 'Patient':
                    patient_id = resource.get('id')
                    break
            
            # Store all resources
            for entry in entries:
                resource = entry.get('resource', {})
                resource_type = resource.get('resourceType')
                fhir_id = resource.get('id')
                
                if not resource_type or not fhir_id:
                    logger.warning(f"Skipping entry: missing resourceType or id")
                    continue
                
                # For non-patient resources, link to patient
                resource_patient_id = None
                if resource_type != 'Patient':
                    # Try to extract patient reference
                    subject = resource.get('subject', {})
                    if isinstance(subject, dict):
                        ref = subject.get('reference', '')
                        if ref.startswith('Patient/'):
                            resource_patient_id = ref.split('/')[-1]
                    else:
                        resource_patient_id = patient_id
                else:
                    resource_patient_id = patient_id
                
                # Check if exists
                existing = FHIRResource.query.filter_by(fhir_id=fhir_id).first()
                
                if existing:
                    existing.data = resource
                    existing.patient_fhir_id = resource_patient_id
                    existing.updated_at = datetime.utcnow()
                    logger.info(f"Updated {resource_type}:{fhir_id}")
                else:
                    fhir_res = FHIRResource(
                        fhir_id=fhir_id,
                        resource_type=resource_type,
                        patient_fhir_id=resource_patient_id,
                        data=resource,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(fhir_res)
                    logger.info(f"Created {resource_type}:{fhir_id}")
            
            db.session.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error storing FHIR bundle: {str(e)}")
            db.session.rollback()
            return False
   
    @staticmethod
    def store_fhir_resource(fhir_data, patient_fhir_id=None, pseudonym_id=None):
        """
        Store a single FHIR resource in the database (original method)
        """
        try:
            resource_type = fhir_data.get('resourceType')
            fhir_id = fhir_data.get('id')
           
            if not resource_type or not fhir_id:
                logger.error("Missing resourceType or id in FHIR data")
                return False
           
            # Check if resource already exists
            existing = FHIRResource.query.filter_by(fhir_id=fhir_id).first()
            if existing:
                # Update existing resource
                existing.data = fhir_data
                existing.patient_fhir_id = patient_fhir_id
                existing.pseudonym_id = pseudonym_id
                existing.updated_at = datetime.utcnow()
                logger.info(f"Updated FHIR resource {resource_type}:{fhir_id}")
            else:
                # Create new resource
                resource = FHIRResource(
                    fhir_id=fhir_id,
                    resource_type=resource_type,
                    patient_fhir_id=patient_fhir_id,
                    data=fhir_data,
                    pseudonym_id=pseudonym_id,
                    created_at=datetime.utcnow()
                )
                db.session.add(resource)
                logger.info(f"Stored FHIR resource {resource_type}:{fhir_id}")
           
            db.session.commit()
            return True
           
        except Exception as e:
            logger.error(f"Error storing FHIR resource: {str(e)}")
            db.session.rollback()
            return False
   
    @staticmethod
    def get_patient_bundle(patient_fhir_id):
        """
        Get complete patient bundle with ALL related resources.
        Returns searchset Bundle (compatible with frontend).
        """
        try:
            # Get patient resource
            patient = FHIRResource.query.filter_by(
                fhir_id=patient_fhir_id,
                resource_type='Patient'
            ).first()
           
            if not patient:
                logger.warning(f"Patient {patient_fhir_id} not found")
                return None
           
            # Get all related resources (NEW: includes all types)
            observations = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,
                resource_type='Observation'
            ).all()
           
            conditions = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,
                resource_type='Condition'
            ).all()
            
            # NEW RESOURCES
            medications = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,
                resource_type='MedicationStatement'
            ).all()
            
            procedures = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,
                resource_type='Procedure'
            ).all()
            
            encounters = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,
                resource_type='Encounter'
            ).all()
           
            # Build searchset Bundle (for read operations)
            bundle = {
                'resourceType': 'Bundle',
                'type': 'searchset',
                'total': 1 + len(observations) + len(conditions) + len(medications) + len(procedures) + len(encounters),
                'entry': [
                    {
                        'resource': patient.data,
                        'fullUrl': f"Patient/{patient.fhir_id}"
                    }
                ]
            }
           
            # Add observations
            for obs in observations:
                bundle['entry'].append({
                    'resource': obs.data,
                    'fullUrl': f"Observation/{obs.fhir_id}"
                })
           
            # Add conditions
            for cond in conditions:
                bundle['entry'].append({
                    'resource': cond.data,
                    'fullUrl': f"Condition/{cond.fhir_id}"
                })
            
            # Add medications (NEW)
            for med in medications:
                bundle['entry'].append({
                    'resource': med.data,
                    'fullUrl': f"MedicationStatement/{med.fhir_id}"
                })
            
            # Add procedures (NEW)
            for proc in procedures:
                bundle['entry'].append({
                    'resource': proc.data,
                    'fullUrl': f"Procedure/{proc.fhir_id}"
                })
            
            # Add encounters (NEW)
            for enc in encounters:
                bundle['entry'].append({
                    'resource': enc.data,
                    'fullUrl': f"Encounter/{enc.fhir_id}"
                })
           
            logger.info(f"Generated bundle for patient {patient_fhir_id} with {len(bundle['entry'])} entries")
            return bundle
           
        except Exception as e:
            logger.error(f"Error generating patient bundle: {str(e)}")
            return None
   
    @staticmethod
    def search_resources(resource_type, filters=None, limit=100, offset=0):
        """Search for FHIR resources with filters (UPDATED to handle new types)"""
        try:
            query = FHIRResource.query.filter_by(resource_type=resource_type)
           
            if filters:
                if 'patient_fhir_id' in filters and filters['patient_fhir_id']:
                    query = query.filter_by(patient_fhir_id=filters['patient_fhir_id'])
           
            total = query.count()
            resources = query.offset(offset).limit(limit).all()
            
            return {
                'resources': [r.data for r in resources],
                'total': total,
                'count': len(resources)
            }
           
        except Exception as e:
            logger.error(f"Error searching resources: {str(e)}")
            return {
                'resources': [],
                'total': 0,
                'count': 0
            }
   
    @staticmethod
    def delete_patient_data(patient_fhir_id):
        """
        Delete all data for a patient (GDPR - Right to be Forgotten)
        Now deletes ALL resource types
        """
        try:
            # Delete all resource types for this patient
            count = 0
            resource_types = ['Patient', 'Observation', 'Condition', 'MedicationStatement', 'Procedure', 'Encounter']
            
            for res_type in resource_types:
                deleted = FHIRResource.query.filter_by(
                    patient_fhir_id=patient_fhir_id,
                    resource_type=res_type
                ).delete()
                count += deleted
            
            # Also delete the patient resource itself
            count += FHIRResource.query.filter_by(
                fhir_id=patient_fhir_id,
                resource_type='Patient'
            ).delete()
            
            db.session.commit()
            logger.info(f"Deleted {count} FHIR resources for patient {patient_fhir_id}")
            
            return count
            
        except Exception as e:
            logger.error(f"Error deleting patient data: {str(e)}")
            db.session.rollback()
            return 0
    
    @staticmethod
    def get_resource_by_id(resource_id):
        """Get a single resource by FHIR ID"""
        try:
            resource = FHIRResource.query.filter_by(fhir_id=resource_id).first()
            if resource:
                return resource.data
            return None
        except Exception as e:
            logger.error(f"Error getting resource: {str(e)}")
            return None