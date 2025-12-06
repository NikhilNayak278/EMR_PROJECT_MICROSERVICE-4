# Database Models
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import Index, Text
import json
from sqlalchemy.dialects.postgresql import JSONB

db = SQLAlchemy()


class User(db.Model):
    """User model for authentication and authorization"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='VIEWER')  # ADMIN, DOCTOR, NURSE, PATIENT, VIEWER
    is_active = db.Column(db.Boolean, default=True, index=True)
    department = db.Column(db.String(100), nullable=True)
    license_number = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    access_logs = db.relationship('AccessLog', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'department': self.department,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class FHIRResource(db.Model):
    """Cached FHIR Resources from Harmonization Service"""
    __tablename__ = 'fhir_resources'
    
    id = db.Column(db.Integer, primary_key=True)
    fhir_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    resource_type = db.Column(db.String(100), nullable=False, index=True)  # Patient, Observation, Condition, etc.
    patient_fhir_id = db.Column(db.String(255), nullable=True, index=True)  # Link to patient
    data = db.Column(JSONB, nullable=False)  # JSON data of FHIR resource
    pseudonym_id = db.Column(db.String(255), nullable=True, index=True)  # Link to pseudonymized data
    is_encrypted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_resource_type_patient', 'resource_type', 'patient_fhir_id'),
        Index('idx_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f'<FHIRResource {self.resource_type}:{self.fhir_id}>'
    
    def to_dict(self, include_data=True):
        result = {
            'id': self.id,
            'fhir_id': self.fhir_id,
            'resource_type': self.resource_type,
            'patient_fhir_id': self.patient_fhir_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        if include_data:
            result['data'] = json.loads(self.data) if isinstance(self.data, str) else self.data
        return result


class AccessLog(db.Model):
    """Audit trail for data access"""
    __tablename__ = 'access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    resource_type = db.Column(db.String(100), nullable=True)
    fhir_id = db.Column(db.String(255), nullable=True, index=True)
    patient_fhir_id = db.Column(db.String(255), nullable=True, index=True)
    action = db.Column(db.String(50), nullable=False)  # READ, SEARCH, CREATE, UPDATE, DELETE
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    query_params = db.Column(db.Text, nullable=True)  # JSON of query parameters
    status_code = db.Column(db.Integer, nullable=False)
    response_time_ms = db.Column(db.Float, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_user_created', 'user_id', 'created_at'),
        Index('idx_resource_accessed', 'resource_type', 'fhir_id'),
    )
    
    def __repr__(self):
        return f'<AccessLog {self.action} by {self.user_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'resource_type': self.resource_type,
            'fhir_id': self.fhir_id,
            'patient_fhir_id': self.patient_fhir_id,
            'action': self.action,
            'status_code': self.status_code,
            'response_time_ms': self.response_time_ms,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class TokenBlacklist(db.Model):
    """Blacklist for revoked tokens"""
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True, index=True)  # JWT ID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    
    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'


class PermissionMatrix(db.Model):
    """Define role-based permissions for different endpoints"""
    __tablename__ = 'permission_matrix'
    
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(50), nullable=False, index=True)
    resource_type = db.Column(db.String(100), nullable=False)  # Patient, Observation, etc. or '*' for all
    action = db.Column(db.String(50), nullable=False)  # READ, SEARCH, CREATE, UPDATE, DELETE or '*' for all
    can_access_own_data_only = db.Column(db.Boolean, default=False)
    
    __table_args__ = (
        Index('idx_role_resource', 'role', 'resource_type', 'action'),
    )
    
    def __repr__(self):
        return f'<Permission {self.role}:{self.resource_type}:{self.action}>'
    
    def to_dict(self):
        return {
            'role': self.role,
            'resource_type': self.resource_type,
            'action': self.action,
            'can_access_own_data_only': self.can_access_own_data_only
        }