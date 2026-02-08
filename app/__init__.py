import os
import json
import logging
from flask import Flask, session
from datetime import timedelta
from .config import Config
from .extensions import db, limiter
from .services.medical_service import highlight_entities

audio_model = None

def create_app(config_class=Config):
    app = Flask(__name__, 
                template_folder='../templates', 
                static_folder='../static')
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    limiter.init_app(app)

    # Attach audio_model to app object for tests and services
    app.audio_model = None

    from .utils import load_translations, ratelimit_handler, TRANSLATIONS
    load_translations(app.root_path)
    app.translations = TRANSLATIONS
    app.register_error_handler(429, ratelimit_handler)

    # Register Jinja filters
    app.jinja_env.filters["ner_highlight"] = highlight_entities

    # Register Blueprints
    from .routes.auth import auth_bp
    from .routes.patient import patient_bp
    from .routes.doctor import doctor_bp
    from .routes.admin import admin_bp
    from .routes.main import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(patient_bp)
    app.register_blueprint(doctor_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(main_bp)

    @app.before_request
    def make_session_permanent():
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=15)

    with app.app_context():
        db.create_all()

    return app
