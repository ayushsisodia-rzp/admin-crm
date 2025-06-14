import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'  # CHANGE THIS IN PRODUCTION
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx'}  # Include necessary file types
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

    # PostgreSQL connection configuration
    PG_USER = os.environ.get('PG_USER') 
    PG_PASSWORD = os.environ.get('PG_PASSWORD') 
    PG_HOST = os.environ.get('PG_HOST') 
    PG_PORT = os.environ.get('PG_PORT') 
    PG_DBNAME = os.environ.get('PG_DBNAME') 


# Ensure upload directory exists
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
