# # Unit Tests for Data Access Service
# import unittest
# import json
# from app import create_app, db
# from models import User, FHIRResource, AccessLog
# from auth_service import AuthService


# class DataAccessServiceTestCase(unittest.TestCase):
#     """Test cases for Data Access Service"""
    
#     def setUp(self):
#         """Set up test client and database"""
#         self.app = create_app('testing')
#         self.client = self.app.test_client()
        
#         with self.app.app_context():
#             db.create_all()
            
#             # Create test user
#             self.test_user = User(
#                 username='testuser',
#                 email='test@emr.com',
#                 password_hash=AuthService.hash_password('testpass123'),
#                 role='DOCTOR',
#                 is_active=True
#             )
#             db.session.add(self.test_user)
#             db.session.commit()
    
#     def tearDown(self):
#         """Clean up after tests"""
#         with self.app.app_context():
#             db.session.remove()
#             db.drop_all()
    
#     def test_health_check(self):
#         """Test health check endpoint"""
#         response = self.client.get('/api/health')
#         self.assertEqual(response.status_code, 200)
#         data = json.loads(response.data)
#         self.assertEqual(data['status'], 'healthy')
    
#     def test_user_registration(self):
#         """Test user registration"""
#         response = self.client.post('/api/auth/register', json={
#             'username': 'newuser',
#             'email': 'newuser@emr.com',
#             'password': 'newpass123',
#             'role': 'VIEWER'
#         })
#         self.assertEqual(response.status_code, 201)
#         data = json.loads(response.data)
#         self.assertEqual(data['user']['username'], 'newuser')
    
#     def test_user_login(self):
#         """Test user login"""
#         response = self.client.post('/api/auth/login', json={
#             'username': 'testuser',
#             'password': 'testpass123'
#         })
#         self.assertEqual(response.status_code, 200)
#         data = json.loads(response.data)
#         self.assertIn('tokens', data)
#         self.assertIn('access_token', data['tokens'])
    
#     def test_login_invalid_credentials(self):
#         """Test login with invalid credentials"""
#         response = self.client.post('/api/auth/login', json={
#             'username': 'testuser',
#             'password': 'wrongpassword'
#         })
#         self.assertEqual(response.status_code, 401)
    
#     def test_token_verification(self):
#         """Test token verification"""
#         # Login first
#         login_response = self.client.post('/api/auth/login', json={
#             'username': 'testuser',
#             'password': 'testpass123'
#         })
#         token = json.loads(login_response.data)['tokens']['access_token']
        
#         # Verify token
#         response = self.client.get('/api/auth/verify', headers={
#             'Authorization': f'Bearer {token}'
#         })
#         self.assertEqual(response.status_code, 200)
#         data = json.loads(response.data)
#         self.assertTrue(data['valid'])
    
#     def test_access_without_token(self):
#         """Test accessing protected endpoint without token"""
#         response = self.client.get('/api/fhir/Patient/123')
#         self.assertEqual(response.status_code, 401)
    
#     def test_fhir_resource_storage(self):
#         """Test storing FHIR resource"""
#         with self.app.app_context():
#             fhir_data = {
#                 'resourceType': 'Patient',
#                 'id': 'patient-001',
#                 'name': [{
#                     'given': ['John'],
#                     'family': 'Doe'
#                 }]
#             }
            
#             result = FHIRService.store_fhir_resource(fhir_data)
#             self.assertTrue(result)
            
#             # Verify resource was stored
#             resource = FHIRResource.query.filter_by(fhir_id='patient-001').first()
#             self.assertIsNotNone(resource)
#             self.assertEqual(resource.resource_type, 'Patient')
    
#     def test_audit_logging(self):
#         """Test audit logging"""
#         with self.app.app_context():
#             AuditService.log_access(
#                 user_id=self.test_user.id,
#                 action='READ',
#                 resource_type='Patient',
#                 fhir_id='patient-001',
#                 status_code=200
#             )
            
#             logs = AccessLog.query.filter_by(user_id=self.test_user.id).all()
#             self.assertEqual(len(logs), 1)
#             self.assertEqual(logs[0].action, 'READ')


# if __name__ == '__main__':
#     unittest.main()