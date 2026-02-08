import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a_very_secret_key')
    DEBUG = False
    TESTING = False
    # Add other common configurations here
    # For example, database URI (if using a database)
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
