"""
Main Flask Application
"""
import os
import logging
from flask import Flask
from flask_cors import CORS
from config import config
from models import db
from routes_extended import auth_bp, fhir_bp, admin_bp, health_bp


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
    app.config.from_object(config.get(config_name, config['default']))
   
    # Initialize extensions
    db.init_app(app)
    
    # Configure CORS
    cors_origins = app.config.get('CORS_ORIGINS', ['http://localhost:3000'])
    CORS(app, resources={r"/api/*": {"origins": cors_origins}})
   
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


def main():
    """Main entry point"""
    app = create_app()
   
    # Enable HTTPS in production
    # For development, use regular HTTP
    if os.getenv('FLASK_ENV') == 'production':
        app.run(
            host='0.0.0.0',
            port=int(os.getenv('FLASK_RUN_PORT', 5000)),
            debug=False,
            ssl_context='adhoc'  # Requires pyopenssl
        )
    else:
        app.run(
            host='0.0.0.0',
            port=int(os.getenv('FLASK_RUN_PORT', 5000)),
            debug=True
        )


if __name__ == '__main__':
    main()