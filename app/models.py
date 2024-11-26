
# app/models.py
from flask_login import UserMixin
from datetime import datetime
from app import db  # Import db here directly

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    files = db.relationship('File', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def get_id(self):
        return str(self.id)
    
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    encrypted_file = db.Column(db.LargeBinary, nullable=False)
    key = db.Column(db.LargeBinary, nullable=False)  # Store the key securely
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_malicious = db.Column(db.Boolean, default=False)


    def __repr__(self):
        return f"File('{self.filename}', '{self.upload_date}', Malicious={self.is_malicious})"

# from app import db

# class File(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     filename = db.Column(db.String(255), nullable=False)
#     encrypted_file = db.Column(db.LargeBinary, nullable=False)  # Stores binary data
#     key = db.Column(db.LargeBinary, nullable=False)  # Encryption key
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

#     def __repr__(self):
#         return f"File('{self.filename}', User ID: {self.user_id})"
