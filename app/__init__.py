# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
#from app.routes import routes

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
migrate = Migrate()

# Initialize the login manager
login_manager.login_view = "routes.login"

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions with the app
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    # Register routes blueprint
    from app.routes import routes
    app.register_blueprint(routes)

    return app

# Define user_loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from app.models import User  # Importing here avoids circular import
    return User.query.get(int(user_id))  # Retrieve user by ID
