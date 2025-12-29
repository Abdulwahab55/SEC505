"""
Configuration File for IDS System
Store sensitive information in environment variables or .env file
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'change-this-to-random-secret-key')
    DEBUG = os.getenv('DEBUG', 'False') == 'True'
    
    # Database Configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'root')
    DB_NAME = os.getenv('DB_NAME', 'projDB')
    
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network Capture Configuration
    NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'eth1')
    CAPTURE_DURATION = int(os.getenv('CAPTURE_DURATION', '60'))  # seconds
    
    # Alert Thresholds
    ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', '40'))  # percentage
    REPORT_THRESHOLD = int(os.getenv('REPORT_THRESHOLD', '10'))  # percentage
    
    # Directory Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MODELS_DIR = os.path.join(BASE_DIR, 'trained_models')
    REPORTS_DIR = os.path.join(BASE_DIR, 'Reports')
    NETWORK_TRAFFIC_DIR = os.path.join(BASE_DIR, 'Network_traffic')
    FLOW_DATA_DIR = os.path.join(BASE_DIR, 'flow_data')
    STATIC_DIR = os.path.join(BASE_DIR, '..', 'IDS', 'static')
    TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
    
    # Queue Configuration
    CAPTURE_QUEUE_MAX = int(os.getenv('CAPTURE_QUEUE_MAX', '5'))
    PROCESSING_QUEUE_MAX = int(os.getenv('PROCESSING_QUEUE_MAX', '5'))
    PREDICTION_QUEUE_MAX = int(os.getenv('PREDICTION_QUEUE_MAX', '10'))
    
    # Performance Configuration
    PROCESSING_TIMEOUT = int(os.getenv('PROCESSING_TIMEOUT', '300'))  # seconds
    STATS_REPORT_INTERVAL = int(os.getenv('STATS_REPORT_INTERVAL', '60'))  # seconds
    
    # Attack Models Configuration
    ATTACK_MODELS = [
        'Bot_Attack',
        'SSH-Patator',
        'FTP-Patator',
        'DoS GoldenEye',
        'DoS Hulk',
        'DoS slowloris',
        'DoS Slowhttptest',
        'Port_Scan',
        'Web Attack'
    ]
    
    @staticmethod
    def create_directories():
        """Create necessary directories if they don't exist"""
        directories = [
            Config.MODELS_DIR,
            Config.REPORTS_DIR,
            Config.NETWORK_TRAFFIC_DIR,
            Config.FLOW_DATA_DIR,
            Config.STATIC_DIR
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            print(f"✓ Directory ready: {directory}")


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Override with stricter settings
    SECRET_KEY = os.getenv('SECRET_KEY')  # Must be set in production
    
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in production environment")


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    
    # Use separate test database
    DB_NAME = 'projDB_test'
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{Config.DB_USER}:{Config.DB_PASSWORD}@{Config.DB_HOST}:{Config.DB_PORT}/{DB_NAME}'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """Get configuration object based on environment"""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'default')
    
    return config.get(config_name, DevelopmentConfig)
