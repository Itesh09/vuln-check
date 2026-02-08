from flask import Flask

def create_app():
    app = Flask(__name__)

    # Load configuration
    app.config.from_object('app.config.base.Config')
    
    # TODO: Register extensions
    # TODO: Register blueprints

    return app
