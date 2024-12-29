import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')  # Fallback value if .env is missing

    # Database configuration
    DATABASE_HOST = os.getenv('DATABASE_HOST')
    DATABASE_PORT = os.getenv('DATABASE_PORT')
    DATABASE_USER = os.getenv('DATABASE_USER')
    DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
    DATABASE_NAME = os.getenv('DATABASE_NAME')

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DATABASE_USER}:{DATABASE_PASSWORD}@"
        f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}") if all([
            DATABASE_USER, DATABASE_PASSWORD, DATABASE_HOST, DATABASE_PORT,
            DATABASE_NAME
        ]) else 'sqlite:///default.db'  # Fallback value

    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Recommended for performance

    # Mail configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.example.com')  # Fallback value
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))  # Convert to integer
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'  # Convert to boolean
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'default@example.com')  # Fallback value
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'default-password')  # Fallback value
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'default@example.com')  # Fallback value
