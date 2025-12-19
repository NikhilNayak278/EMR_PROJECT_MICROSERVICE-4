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
        """Get complete patient bundle with all related resources"""
        try:
            # Get patient resource
            patient = FHIRResource.query.filter_by(
                fhir_id=patient_fhir_id,
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