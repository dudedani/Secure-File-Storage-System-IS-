class Config:
    SECRET_KEY = 'your_secret_key'  # Change to a secure key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'  # SQLite database
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your_email@gmail.com'
    MAIL_PASSWORD = 'your_email_password'
