# Login System Configuration
# Update these values based on your requirements

# Flask Configuration
DEBUG = True
SECRET_KEY = "your_secret_key_here_change_in_production_2024"
HOST = "0.0.0.0"
PORT = 5000

# Session Configuration
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS
SESSION_LIFETIME_HOURS = 24

# Brute Force Protection
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# CAPTCHA Configuration
CAPTCHA_LENGTH = 6
CAPTCHA_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# Validation Rules
USERNAME_MIN_LENGTH = 3
PASSWORD_MIN_LENGTH = 6
USERNAME_PATTERN = "^[a-zA-Z0-9_@.]+$"

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FILE = "logs/login.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Database Configuration
# These should match your commonFunction.py settings
DB_FILE = "tradering.db"  # Update if different
USER_TABLE = "user_dtls"
USER_COLUMN = "user"
PASSWORD_COLUMN = "kite_password"

# Security
ALLOWED_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000"]
USE_HTTPS = False
SECURE_COOKIES = False

# Features
ENABLE_BRUTE_FORCE_PROTECTION = True
ENABLE_CAPTCHA = True
ENABLE_SESSION_TRACKING = True
ENABLE_ACTIVITY_LOGGING = True
