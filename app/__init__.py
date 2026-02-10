from flask import Flask
import os

def create_app():
    # Set template folder to be at project root
    template_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    app = Flask(__name__, template_folder=template_folder)

    # Load configuration
    app.config.from_object('app.config.base.Config')
    
    # Register blueprints
    from app.blueprints.main_routes import main_bp
    from app.blueprints.scan_routes import scan_bp
    from app.blueprints.auth_routes import auth_bp
    from app.blueprints.report_routes import report_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(report_bp)

    return app
