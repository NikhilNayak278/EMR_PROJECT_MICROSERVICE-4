"""
Audit and Logging Service
"""
import logging
import json
from datetime import datetime, timedelta
from flask import request
from models import AccessLog, db
from sqlalchemy import func

logger = logging.getLogger(__name__)


class AuditService:
    """Handle audit logging for all data access"""
   
    @staticmethod
    def log_access(
        user_id,
        action,
        resource_type=None,
        fhir_id=None,
        patient_fhir_id=None,
        status_code=200,
        response_time_ms=None,
        error_message=None
    ):
        """
        Log data access for audit trail
        Called after every API request
        """
        try:
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get('User-Agent', '') if request else None
            query_params = json.dumps(dict(request.args)) if request and request.args else None
           
            access_log = AccessLog(
                user_id=user_id,
                resource_type=resource_type,
                fhir_id=fhir_id,
                patient_fhir_id=patient_fhir_id,
                action=action,
                ip_address=ip_address,
                user_agent=user_agent,
                query_params=query_params,
                status_code=status_code,
                response_time_ms=response_time_ms,
                error_message=error_message,
                created_at=datetime.utcnow()
            )
           
            db.session.add(access_log)
            db.session.commit()
           
            logger.info(
                f"Audit log: User {user_id} performed {action} on "
                f"{resource_type}:{fhir_id} - Status: {status_code}"
            )
           
        except Exception as e:
            logger.error(f"Error logging access: {str(e)}")
            db.session.rollback()
   
    @staticmethod
    def get_access_logs(user_id=None, resource_type=None, limit=100, offset=0):
        """Retrieve access logs for audit purposes (Admin only)"""
        try:
            query = AccessLog.query
           
            if user_id:
                query = query.filter_by(user_id=user_id)
           
            if resource_type:
                query = query.filter_by(resource_type=resource_type)
           
            logs = query.order_by(AccessLog.created_at.desc()).offset(offset).limit(limit).all()
           
            return [log.to_dict() for log in logs]
           
        except Exception as e:
            logger.error(f"Error retrieving access logs: {str(e)}")
            return []
   
    @staticmethod
    def get_user_activity(user_id, days=30):
        """Get activity summary for a specific user"""
        try:
            since = datetime.utcnow() - timedelta(days=days)
           
            activity = AccessLog.query.filter(
                AccessLog.user_id == user_id,
                AccessLog.created_at >= since
            ).all()
           
            # Group by action
            summary = {}
            for log in activity:
                action = log.action
                if action not in summary:
                    summary[action] = 0
                summary[action] += 1
           
            return {
                'user_id': user_id,
                'period_days': days,
                'total_actions': len(activity),
                'actions': summary,
                'last_activity': activity[0].created_at.isoformat() if activity else None
            }
           
        except Exception as e:
            logger.error(f"Error getting user activity: {str(e)}")
            return None
   
    @staticmethod
    def cleanup_old_logs(days_to_keep=90):
        """Remove old audit logs to manage database size"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            deleted_count = AccessLog.query.filter(
                AccessLog.created_at < cutoff_date
            ).delete()
            
            db.session.commit()
            
            logger.info(f"Cleaned up {deleted_count} old audit logs (older than {days_to_keep} days)")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up old logs: {str(e)}")
            db.session.rollback()
            return 0