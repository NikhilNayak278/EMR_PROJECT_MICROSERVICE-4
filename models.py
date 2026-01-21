
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import Index, Text
from sqlalchemy.dialects.postgresql import JSONB

db = SQLAlchemy()

class FHIRResource(db.Model):
    """Cached FHIR Resources from Harmonization Service"""
    __tablename__ = 'fhir_resources'
    
    id = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer, primary_key=True)
    # fhir_id: User requested removal, but DB has NOT NULL constraint. 
    # We will treat this as an internal unique row identifier (UUID) & satisfy DB constraint.
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
            'pseudonym_id': self.pseudonym_id,
            'is_encrypted': self.is_encrypted,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_data:
            result['data'] = self.data
        
        return result


class User(db.Model):
    """System User (Admin/Doctor)"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    can_upload = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Assuming username exists but was hidden in screenshot, or maybe mixed. 
    # Standard practice is 'username' or 'email'. We will assume 'username'.
    username = db.Column(db.String(100), unique=True, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'can_upload': self.can_upload,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }