import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///words.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    
    # Session
    PERMANENT_SESSION_LIFETIME = 604800  # 7 days in seconds
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # APIs
    GROQ_API_KEY = os.getenv('GROQ_API_KEY')
    GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
    
    HUGGINGFACE_API_KEY = os.getenv('HUGGINGFACE_API_KEY')
    HUGGINGFACE_API_URL = "https://api-inference.huggingface.co/models/facebook/nllb-200-distilled-600M"
    headers = {"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"}
    
    # Google OAuth
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_DEFAULT = ["200 per day", "50 per hour"]
