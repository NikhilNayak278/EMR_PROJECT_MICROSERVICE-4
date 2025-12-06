# Main Flask Application
import os
import logging
from flask import Flask
from flask_cors import CORS
from config import config
from models import db
from routes import auth_bp, fhir_bp, admin_bp, health_bp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(config_name=None):
    """Application factory"""
    
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config.get(config_name))
    
    # Initialize extensions
    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": app.config['CORS_ORIGINS']}})
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(fhir_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(health_bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        logger.info("Database tables created/verified")
    
    logger.info(f"Data Access Service initialized in {config_name} mode")
    
    return app


if __name__ == '__main__':
    app = create_app()
    
    # Enable HTTPS in production
    # For development, use regular HTTP
    if os.getenv('FLASK_ENV') == 'production':
        app.run(
            host='0.0.0.0',
            port=5004,
            debug=False,
            ssl_context='adhoc'  # Requires pyopenssl
        )
    else:
        app.run(
            host='0.0.0.0',
            port=5004,
            debug=True
        )