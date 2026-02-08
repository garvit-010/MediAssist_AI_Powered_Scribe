import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-key-123")
    SQLALCHEMY_DATABASE_URI = "sqlite:///medical_data.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # HIPAA Security Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True  # Set to False if testing locally without HTTPS
    
    # AI Config
    OLLAMA_API_URL = "http://localhost:11434/api/generate"
    FERNET_KEY = os.getenv("FERNET_KEY")
