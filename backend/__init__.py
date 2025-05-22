
"""
Backend package for AI-SAST Demo Application
"""

__version__ = "1.0.0"
__author__ = "Demo Team"

# Clean imports
from .app import create_app
from .config import get_config

__all__ = ['create_app', 'get_config']