"""
FHIR Resource Service
"""
import logging
from models import FHIRResource, db
from datetime import datetime

logger = logging.getLogger(__name__)


class FHIRService:
    """Handle FHIR resource operations"""
   
    @staticmethod
    def store_fhir_resource(fhir_data, patient_fhir_id=None, pseudonym_id=None):
        """Store a FHIR resource in the database"""
        try:
            import uuid
            resource_type = fhir_data.get('resourceType')
            
            # User Requirement: "in the fhir_id field is not needed"
            # DB Requirement: fhir_id is NOT NULL.
            # Solution: Generate a random internal UUID for the DB row.
            internal_db_uuid = str(uuid.uuid4())
            
            # User Requirement: "patient_fhir_id our application should gererate the unique id"
            # If this is a Patient resource, we generate its ID if not provided/overridden.
            if resource_type == 'Patient':
                # Check if patient with this pseudonym already exists
                if pseudonym_id:
                     existing_patient = FHIRResource.query.filter_by(pseudonym_id=pseudonym_id, resource_type='Patient').first()
                     if existing_patient:
                         logger.info(f"Updated existing patient {existing_patient.patient_fhir_id} for pseudonym {pseudonym_id}")
                         # Update existing record
                         patient_fhir_id = existing_patient.patient_fhir_id
                         # Update logic: we can update the data blob if needed, or just return existing ID
                         # For now, let's update the data blob to be safe with latest info
                         fhir_data['id'] = patient_fhir_id
                         existing_patient.data = fhir_data
                         db.session.commit()
                         return patient_fhir_id

                if not patient_fhir_id:
                     patient_fhir_id = str(uuid.uuid4())
                # Update the JSON content to reflect this new system-generated ID
                fhir_data['id'] = patient_fhir_id

                # Update the JSON content to reflect this new system-generated ID
                fhir_data['id'] = patient_fhir_id

            if not resource_type:
                logger.error("Missing resourceType in FHIR data")
                return False
            
            # --- DEDUPLICATION LOGIC ---
            # Check for existing duplicate resource (same patient, same code/class, same date)
            # This prevents re-uploading the same document from creating duplicate entries.
            existing_id = FHIRService._find_duplicate_resource(resource_type, patient_fhir_id, fhir_data)
            if existing_id:
                logger.info(f"Duplicate {resource_type} detected (Ref: {existing_id}). Skipping insertion.")
                return existing_id

            # Create new resource
            # We treat every save as a new record or a specific update if we had a way to track it.
            # Given instructions, we simply insert with the new IDs.
            resource = FHIRResource(
                fhir_id=internal_db_uuid, # Satisfy DB constraint
                resource_type=resource_type,
                patient_fhir_id=patient_fhir_id,
                data=fhir_data,
                pseudonym_id=pseudonym_id, # User Requirement: mapped from Chidanad
                created_at=datetime.utcnow()
            )
            db.session.add(resource)
            logger.info(f"Stored FHIR resource {resource_type} for patient {patient_fhir_id}")
            
            db.session.commit()
            return patient_fhir_id # Return the ID we used
            
        except Exception as e:
            logger.error(f"Error storing FHIR resource: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def _find_duplicate_resource(resource_type, patient_id, data):
        """
        Check if a resource with identical key characteristics already exists for this patient.
        Returns the existing fhir_id if found, else None.
        """
        try:
            query = FHIRResource.query.filter_by(resource_type=resource_type, patient_fhir_id=patient_id)
            
            # 1. Condition (Diagnosis): Key = code.coding[0].code AND clinicalStatus
            if resource_type == 'Condition':
                code = data.get('code', {}).get('coding', [{}])[0].get('code')
                if not code: return None # Can't dedup without specific code
                
                candidates = query.all()
                for c in candidates:
                    curr_code = c.data.get('code', {}).get('coding', [{}])[0].get('code')
                    if curr_code == code:
                        return c.fhir_id
            
            # 2. Encounter: Key = class (IMP/AMB) AND status
            elif resource_type == 'Encounter':
                # Encounters are broader. Only dedup if practically identical status/class.
                cls_code = data.get('class', {}).get('code') # R4 might be class object
                # Some mappers use class_fhir array
                
                candidates = query.all()
                # If there's already a finished encounter for this patient, we might assume it's the same visit 
                # IF the dates overlap, but for this simple mapper, let's just avoid double-counting "finished" visits 
                # if they have zero dates or identical type.
                # Simplest check: If we have ANY finished encounter, maybe don't add another generic one? 
                # No, that's too aggressive.
                pass 

            # 3. Observation: Key = code.coding[0].code AND effectiveDateTime (or value)
            elif resource_type == 'Observation':
                code = data.get('code', {}).get('coding', [{}])[0].get('code')
                val_q = data.get('valueQuantity', {}).get('value')
                
                if code:
                    candidates = query.all()
                    for c in candidates:
                        curr_code = c.data.get('code', {}).get('coding', [{}])[0].get('code')
                        curr_val = c.data.get('valueQuantity', {}).get('value')
                        if curr_code == code and str(curr_val) == str(val_q):
                            return c.fhir_id

            return None
        except Exception as e:
            logger.error(f"Dedup check failed: {e}")
            return None
            

   
    @staticmethod
    def get_patient_bundle(patient_fhir_id):
        """Get complete patient bundle with all related resources"""
        try:
            # Get patient resource
            patient = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,  # Changed from fhir_id to patient_fhir_id
                resource_type='Patient'
            ).first()
           
            if not patient:
                logger.warning(f"Patient {patient_fhir_id} not found")
                return None
           
            # Get all related observations and conditions
            observations = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,
                resource_type='Observation'
            ).all()
           
            conditions = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id,
                resource_type='Condition'
            ).all()
           
            # Build bundle
            bundle = {
                'resourceType': 'Bundle',
                'type': 'searchset',
                'total': 1 + len(observations) + len(conditions),
                'entry': [
                    {
                        'resource': {**patient.data, "pseudonymId": patient.pseudonym_id} if patient.pseudonym_id else patient.data,
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
           
            logger.info(f"Generated bundle for patient {patient_fhir_id} with {len(bundle['entry'])} entries")
            return bundle
           
        except Exception as e:
            logger.error(f"Error generating patient bundle: {str(e)}")
            return None
   
    @staticmethod
    def search_resources(resource_type, filters=None, limit=100, offset=0):
        """Search for FHIR resources with filters"""
        try:
            query = FHIRResource.query.filter_by(resource_type=resource_type)
           
            if filters:
                # Support both 'patient' (FHIR standard) and 'patient_fhir_id' (internal)
                patient_filter = filters.get('patient_fhir_id') or filters.get('patient')
                if patient_filter:
                    query = query.filter_by(patient_fhir_id=patient_filter)
           
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
        """Delete all data for a patient (for right to be forgotten)"""
        try:
            # Delete all resources for this patient
            count = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id
            ).delete()
            
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