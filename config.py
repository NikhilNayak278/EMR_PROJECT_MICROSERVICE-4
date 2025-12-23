"""
Data Access Service Configuration
Extended FHIR Support with MS3 Integration
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base Configuration"""
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Extended to 24 hours
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///data_access_service.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    
    # Security
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
    
    # API Configuration
    MAX_RESULTS_PER_PAGE = 100
    DEFAULT_PAGE_SIZE = 20
    
    # MS3 Integration Configuration
    MS3_API_BASE_URL = os.getenv('MS3_API_BASE_URL', 'http://localhost:5005')
    MS3_API_TIMEOUT = int(os.getenv('MS3_API_TIMEOUT', '30'))
    
    # FHIR Configuration
    SUPPORTED_FHIR_RESOURCES = [
        'Patient', 'Observation', 'Condition', 
        'MedicationStatement', 'Procedure', 'Encounter',
        'Bundle'
    ]
    
    # Audit Configuration
    ENABLE_AUDIT_LOGGING = os.getenv('ENABLE_AUDIT_LOGGING', 'true').lower() == 'true'
    AUDIT_LOG_RETENTION_DAYS = int(os.getenv('AUDIT_LOG_RETENTION_DAYS', '90'))
    
    # Performance Configuration
    DATABASE_POOL_SIZE = int(os.getenv('DATABASE_POOL_SIZE', '10'))
    DATABASE_POOL_RECYCLE = int(os.getenv('DATABASE_POOL_RECYCLE', '3600'))
    DATABASE_POOL_PRE_PING = True


class DevelopmentConfig(Config):
    """Development Configuration"""
    DEBUG = True
    SQLALCHEMY_ECHO = True
    TESTING = False


class TestingConfig(Config):
    """Testing Configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    DEBUG = True
    ENABLE_AUDIT_LOGGING = False


class ProductionConfig(Config):
    """Production Configuration"""
    DEBUG = False
    SQLALCHEMY_ECHO = False
    TESTING = False
    # Force HTTPS in production
    PREFERRED_URL_SCHEME = 'https'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}