import os

def get_config():
    """Get configuration based on environment - clean function"""
    env = os.getenv('FLASK_ENV', 'development')
    
    if env == 'production':
        from .database import ProductionConfig
        return ProductionConfig
    elif env == 'testing':
        from .database import TestingConfig
        return TestingConfig
    else:
        from .database import DevelopmentConfig
        return DevelopmentConfig

# Clean exports
__all__ = ['get_config']