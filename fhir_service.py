# # FHIR Data Access and Query Service
# import requests
# import json
# import logging
# from datetime import datetime
# from flask import current_app
# from models import FHIRResource, db

# logger = logging.getLogger(__name__)


# class FHIRService:
#     """Handle FHIR resource operations and queries"""
    
#     @staticmethod
#     def fetch_fhir_resources_from_harmonization(batch_size=50):
#         """
#         Fetch FHIR resources from Harmonization Service (Microservice 3)
#         This would be called periodically or on-demand
#         """
#         try:
#             url = f"{current_app.config['HARMONIZATION_SERVICE_URL']}/api/fhir/resources"
            
#             headers = {
#                 'Content-Type': 'application/json',
#                 'Accept': 'application/fhir+json'
#             }
            
#             params = {
#                 'batch_size': batch_size,
#                 'validated': True
#             }
            
#             response = requests.get(url, headers=headers, params=params, timeout=10)
            
#             if response.status_code == 200:
#                 resources = response.json().get('resources', [])
#                 return resources
#             else:
#                 logger.error(f"Failed to fetch from Harmonization Service: {response.status_code}")
#                 return None
                
#         except Exception as e:
#             logger.error(f"Error fetching from Harmonization Service: {str(e)}")
#             return None
    
#     @staticmethod
#     def store_fhir_resource(resource_data):
#         """
#         Store FHIR resource in local database
#         resource_data should be valid FHIR JSON
#         """
#         try:
#             # Extract key information from FHIR resource
#             resource_type = resource_data.get('resourceType', 'Unknown')
#             fhir_id = resource_data.get('id', '')
            
#             # Get patient reference if applicable
#             patient_fhir_id = None
#             if 'subject' in resource_data and 'reference' in resource_data['subject']:
#                 patient_fhir_id = resource_data['subject']['reference'].split('/')[-1]
            
#             # Check if resource already exists
#             existing = FHIRResource.query.filter_by(fhir_id=fhir_id).first()
            
#             if existing:
#                 # Update existing resource
#                 existing.data = json.dumps(resource_data)
#                 existing.updated_at = datetime.utcnow()
#                 logger.info(f"Updated FHIR resource: {resource_type}:{fhir_id}")
#             else:
#                 # Create new resource
#                 fhir_resource = FHIRResource(
#                     fhir_id=fhir_id,
#                     resource_type=resource_type,
#                     patient_fhir_id=patient_fhir_id,
#                     data=json.dumps(resource_data),
#                     is_encrypted=False
#                 )
#                 db.session.add(fhir_resource)
#                 logger.info(f"Stored new FHIR resource: {resource_type}:{fhir_id}")
            
#             db.session.commit()
#             return True
            
#         except Exception as e:
#             logger.error(f"Error storing FHIR resource: {str(e)}")
#             db.session.rollback()
#             return False
    
#     @staticmethod
#     def get_resource_by_id(resource_type, resource_id):
#         """Get FHIR resource by ID and type"""
#         try:
#             resource = FHIRResource.query.filter_by(
#                 resource_type=resource_type,
#                 fhir_id=resource_id
#             ).first()
            
#             if resource:
#                 return json.loads(resource.data)
#             return None
            
#         except Exception as e:
#             logger.error(f"Error retrieving resource: {str(e)}")
#             return None
    
#     @staticmethod
#     def search_resources(resource_type, **filters):
#         """
#         Search FHIR resources with filters
#         Supports filters like: patient_id, status, date_from, date_to, etc.
#         """
#         try:
#             query = FHIRResource.query.filter_by(resource_type=resource_type)
            
#             # Apply filters
#             if 'patient_id' in filters and filters['patient_id']:
#                 query = query.filter_by(patient_fhir_id=filters['patient_id'])
            
#             if 'status' in filters and filters['status']:
#                 # Search within JSON data for status field
#                 # This is simplified - in production use JSON query operators
#                 query = query.all()
#                 filtered_results = []
#                 for resource in query:
#                     data = json.loads(resource.data)
#                     if data.get('status') == filters['status']:
#                         filtered_results.append(resource)
#                 query = filtered_results
#             else:
#                 query = query.all()
            
#             if 'date_from' in filters and filters['date_from']:
#                 date_from = datetime.fromisoformat(filters['date_from'])
#                 query = [r for r in query if r.created_at >= date_from] if isinstance(query, list) else query.filter(FHIRResource.created_at >= date_from)
            
#             if 'date_to' in filters and filters['date_to']:
#                 date_to = datetime.fromisoformat(filters['date_to'])
#                 query = [r for r in query if r.created_at <= date_to] if isinstance(query, list) else query.filter(FHIRResource.created_at <= date_to)
            
#             # Apply pagination
#             page = int(filters.get('page', 1))
#             per_page = int(filters.get('per_page', current_app.config['DEFAULT_PAGE_SIZE']))
            
#             if isinstance(query, list):
#                 start = (page - 1) * per_page
#                 end = start + per_page
#                 results = query[start:end]
#                 total = len(query)
#             else:
#                 results = query.paginate(page=page, per_page=per_page)
#                 total = results.total
#                 results = results.items
            
#             return {
#                 'resources': [json.loads(r.data) for r in results],
#                 'total': total,
#                 'page': page,
#                 'per_page': per_page
#             }
            
#         except Exception as e:
#             logger.error(f"Error searching resources: {str(e)}")
#             return None
    
#     @staticmethod
#     def get_patient_bundle(patient_id):
#         """
#         Get all FHIR resources related to a patient
#         Returns a FHIR Bundle resource
#         """
#         try:
#             # Get patient resource
#             patient_resource = FHIRResource.query.filter_by(
#                 resource_type='Patient',
#                 fhir_id=patient_id
#             ).first()
            
#             if not patient_resource:
#                 return None
            
#             # Get all related resources (observations, conditions, medications, etc.)
#             related_resources = FHIRResource.query.filter_by(
#                 patient_fhir_id=patient_id
#             ).all()
            
#             # Create FHIR Bundle
#             bundle = {
#                 'resourceType': 'Bundle',
#                 'type': 'searchset',
#                 'total': len(related_resources) + 1,
#                 'entry': []
#             }
            
#             # Add patient resource
#             bundle['entry'].append({
#                 'resource': json.loads(patient_resource.data)
#             })
            
#             # Add related resources
#             for resource in related_resources:
#                 bundle['entry'].append({
#                     'resource': json.loads(resource.data)
#                 })
            
#             return bundle
            
#         except Exception as e:
#             logger.error(f"Error getting patient bundle: {str(e)}")
#             return None
"""
FHIR Service - Handle FHIR resource operations
"""
import json
import logging
from datetime import datetime
from models import db, FHIRResource
from sqlalchemy import cast, String

logger = logging.getLogger(__name__)

class FHIRService:
    """Service for FHIR resource management"""
    
    @staticmethod
    def search_resources(resource_type, filters=None, page=1, per_page=20):
        """
        Search FHIR resources with filters and pagination
        
        Args:
            resource_type (str): Type of FHIR resource (Patient, Observation, etc.)
            filters (dict): Optional filters to apply
            page (int): Page number for pagination
            per_page (int): Number of results per page
            
        Returns:
            dict: Search results with resources and pagination info
        """
        try:
            # Build base query
            query = FHIRResource.query.filter_by(resource_type=resource_type)
            
            # Apply filters if provided
            if filters:
                for key, value in filters.items():
                    if key == 'patient':
                        # Handle patient reference filter
                        query = query.filter(FHIRResource.patient_fhir_id == value)
                    
                    elif key == 'name':
                        # Search in name field (JSONB) - convert to string for search
                        query = query.filter(
                            cast(FHIRResource.data['name'], String).contains(value)
                        )
                    
                    elif key == 'gender':
                        # Search exact gender match
                        query = query.filter(
                            FHIRResource.data['gender'].astext == value
                        )
                    
                    elif key == 'birthdate':
                        # Search exact birthdate match
                        query = query.filter(
                            FHIRResource.data['birthDate'].astext == value
                        )
                    
                    elif key == 'code':
                        # Search in code field for Observations/Conditions
                        query = query.filter(
                            cast(FHIRResource.data['code'], String).contains(value)
                        )
                    
                    elif key == 'status':
                        # Search by status
                        query = query.filter(
                            FHIRResource.data['status'].astext == value
                        )
            
            # Get total count before pagination
            total = query.count()
            
            # Apply pagination
            resources = query.offset((page - 1) * per_page).limit(per_page).all()
            
            # Extract data - JSONB returns dict directly, no parsing needed
            result = []
            for resource in resources:
                # Data is already a Python dict from JSONB column
                result.append(resource.data)
            
            return {
                'resources': result,
                'total': total,
                'page': page,
                'per_page': per_page
            }
            
        except Exception as e:
            logger.error(f"Error searching resources: {str(e)}")
            import traceback
            traceback.print_exc()
            raise
    
    @staticmethod
    def get_resource(resource_type, fhir_id):
        """
        Get a specific FHIR resource by type and ID
        
        Args:
            resource_type (str): Type of FHIR resource
            fhir_id (str): FHIR resource ID
            
        Returns:
            dict: FHIR resource data or None if not found
        """
        try:
            resource = FHIRResource.query.filter_by(
                resource_type=resource_type,
                fhir_id=fhir_id
            ).first()
            
            if not resource:
                return None
            
            # Data is already a dict from JSONB column
            return resource.data
            
        except Exception as e:
            logger.error(f"Error getting resource: {str(e)}")
            raise
    
    @staticmethod
    def store_resource(resource_data, patient_fhir_id=None):
        """
        Store a FHIR resource in the database
        
        Args:
            resource_data (dict): FHIR resource data
            patient_fhir_id (str): Patient FHIR ID (for linking)
            
        Returns:
            dict: Stored resource information
        """
        try:
            resource_type = resource_data.get('resourceType')
            fhir_id = resource_data.get('id')
            
            if not resource_type or not fhir_id:
                raise ValueError("Resource must have resourceType and id")
            
            # Check if resource already exists
            existing = FHIRResource.query.filter_by(fhir_id=fhir_id).first()
            
            if existing:
                # Update existing resource
                existing.data = resource_data  # JSONB handles dict directly
                existing.resource_type = resource_type
                existing.patient_fhir_id = patient_fhir_id or existing.patient_fhir_id
                existing.updated_at = datetime.utcnow()
                db.session.commit()
                
                logger.info(f"Updated {resource_type} resource: {fhir_id}")
                return existing.to_dict()
            else:
                # Create new resource
                new_resource = FHIRResource(
                    fhir_id=fhir_id,
                    resource_type=resource_type,
                    patient_fhir_id=patient_fhir_id,
                    data=resource_data,  # JSONB handles dict directly
                    created_at=datetime.utcnow()
                )
                db.session.add(new_resource)
                db.session.commit()
                
                logger.info(f"Created {resource_type} resource: {fhir_id}")
                return new_resource.to_dict()
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error storing resource: {str(e)}")
            raise
    
    @staticmethod
    def delete_resource(resource_type, fhir_id):
        """
        Delete a FHIR resource
        
        Args:
            resource_type (str): Type of FHIR resource
            fhir_id (str): FHIR resource ID
            
        Returns:
            bool: True if deleted, False if not found
        """
        try:
            resource = FHIRResource.query.filter_by(
                resource_type=resource_type,
                fhir_id=fhir_id
            ).first()
            
            if not resource:
                return False
            
            db.session.delete(resource)
            db.session.commit()
            
            logger.info(f"Deleted {resource_type} resource: {fhir_id}")
            return True
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting resource: {str(e)}")
            raise
    
    @staticmethod
    def get_patient_bundle(patient_fhir_id):
        """
        Get a complete bundle of all resources for a patient
        
        Args:
            patient_fhir_id (str): Patient FHIR ID
            
        Returns:
            dict: FHIR Bundle with all patient resources or None if patient not found
        """
        try:
            # Get patient resource
            patient = FHIRResource.query.filter_by(
                resource_type='Patient',
                fhir_id=patient_fhir_id
            ).first()
            
            if not patient:
                logger.warning(f"Patient not found: {patient_fhir_id}")
                return None
            
            # Get all related resources for this patient
            related_resources = FHIRResource.query.filter_by(
                patient_fhir_id=patient_fhir_id
            ).all()
            
            # Build FHIR Bundle
            bundle = {
                'resourceType': 'Bundle',
                'type': 'searchset',
                'id': f'bundle-{patient_fhir_id}',
                'meta': {
                    'lastUpdated': datetime.utcnow().isoformat() + 'Z'
                },
                'entry': []
            }
            
            # Add patient resource
            bundle['entry'].append({
                'fullUrl': f'Patient/{patient_fhir_id}',
                'resource': patient.data  # Already a dict from JSONB
            })
            
            # Add all related resources (Observations, Conditions, etc.)
            for resource in related_resources:
                # Don't duplicate the patient resource
                if resource.fhir_id != patient_fhir_id:
                    bundle['entry'].append({
                        'fullUrl': f"{resource.resource_type}/{resource.fhir_id}",
                        'resource': resource.data  # Already a dict from JSONB
                    })
            
            # Set total count
            bundle['total'] = len(bundle['entry'])
            
            logger.info(f"Created bundle for patient {patient_fhir_id} with {bundle['total']} resources")
            return bundle
            
        except Exception as e:
            logger.error(f"Error creating patient bundle: {str(e)}")
            import traceback
            traceback.print_exc()
            raise
    
    @staticmethod
    def get_resources_by_patient(resource_type, patient_fhir_id):
        """
        Get all resources of a specific type for a patient
        
        Args:
            resource_type (str): Type of FHIR resource
            patient_fhir_id (str): Patient FHIR ID
            
        Returns:
            list: List of FHIR resources
        """
        try:
            resources = FHIRResource.query.filter_by(
                resource_type=resource_type,
                patient_fhir_id=patient_fhir_id
            ).all()
            
            # Extract data - already dict from JSONB
            result = [resource.data for resource in resources]
            
            logger.info(f"Found {len(result)} {resource_type} resources for patient {patient_fhir_id}")
            return result
            
        except Exception as e:
            logger.error(f"Error getting resources by patient: {str(e)}")
            raise
    
    @staticmethod
    def validate_fhir_resource(resource_data):
        """
        Basic validation of FHIR resource structure
        
        Args:
            resource_data (dict): FHIR resource data
            
        Returns:
            tuple: (is_valid, error_message)
        """
        try:
            # Check if it's a dictionary
            if not isinstance(resource_data, dict):
                return False, "Resource data must be a dictionary"
            
            # Check required fields
            if 'resourceType' not in resource_data:
                return False, "Missing required field: resourceType"
            
            if 'id' not in resource_data:
                return False, "Missing required field: id"
            
            # Validate resource type
            valid_types = ['Patient', 'Observation', 'Condition', 'Procedure', 'Medication', 'Encounter']
            if resource_data['resourceType'] not in valid_types:
                return False, f"Invalid resourceType. Must be one of: {', '.join(valid_types)}"
            
            return True, None
            
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_resource_count_by_type():
        """
        Get count of resources by type
        
        Returns:
            dict: Resource counts by type
        """
        try:
            from sqlalchemy import func
            
            results = db.session.query(
                FHIRResource.resource_type,
                func.count(FHIRResource.id)
            ).group_by(FHIRResource.resource_type).all()
            
            counts = {resource_type: count for resource_type, count in results}
            
            return counts
            
        except Exception as e:
            logger.error(f"Error getting resource counts: {str(e)}")
            raise
