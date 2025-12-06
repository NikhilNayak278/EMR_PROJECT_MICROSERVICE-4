# Data Access Service Configuration
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base Configuration"""
    # Flask
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('DEBUG', True)
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'sqlite:///data_access_service.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    
    # Service URLs (from other microservices)
    HARMONIZATION_SERVICE_URL = os.getenv(
        'HARMONIZATION_SERVICE_URL',
        'http://harmonization-service:5003'
    )
    PRIVACY_SERVICE_URL = os.getenv(
        'PRIVACY_SERVICE_URL',
        'http://privacy-service:5002'
    )
    EXTRACTION_SERVICE_URL = os.getenv(
        'EXTRACTION_SERVICE_URL',
        'http://extraction-service:5001'
    )
    
    # FHIR Server Configuration
    FHIR_SERVER_URL = os.getenv(
        'FHIR_SERVER_URL',
        'http://fhir-server:8080/fhir'
    )
    
    # Security
    CORS_ORIGINS = os.getenv(
        'CORS_ORIGINS',
        'http://localhost:3000,http://localhost:5000'
    ).split(',')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # API Configuration
    MAX_RESULTS_PER_PAGE = 100
    DEFAULT_PAGE_SIZE = 20


class DevelopmentConfig(Config):
    """Development Configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production Configuration"""
    DEBUG = False
    TESTING = False
    SQLALCHEMY_ECHO = False


class TestingConfig(Config):
    """Testing Configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}