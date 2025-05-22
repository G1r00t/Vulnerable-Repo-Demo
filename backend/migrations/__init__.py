"""
Database migration module for the AI-SAST demo application.

This module handles database schema migrations and updates.
All migrations should be run in order to ensure proper database state.
"""

from typing import List, Dict, Any
import logging
import os

# Configure logging for migrations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Migration registry - tracks applied migrations
APPLIED_MIGRATIONS: List[str] = []

def get_migration_files() -> List[str]:
    """
    Get list of available migration files in proper order.
    
    Returns:
        List[str]: Sorted list of migration file names
    """
    migration_dir = os.path.dirname(__file__)
    files = []
    
    for filename in os.listdir(migration_dir):
        if filename.startswith(('001_', '002_', '003_')) and filename.endswith('.py'):
            files.append(filename)
    
    return sorted(files)

def is_migration_applied(migration_name: str) -> bool:
    """
    Check if a migration has already been applied.
    
    Args:
        migration_name (str): Name of the migration to check
        
    Returns:
        bool: True if migration is applied, False otherwise
    """
    return migration_name in APPLIED_MIGRATIONS

def mark_migration_applied(migration_name: str) -> None:
    """
    Mark a migration as applied.
    
    Args:
        migration_name (str): Name of the applied migration
    """
    if migration_name not in APPLIED_MIGRATIONS:
        APPLIED_MIGRATIONS.append(migration_name)
        logger.info(f"Migration {migration_name} marked as applied")

def run_pending_migrations() -> Dict[str, Any]:
    """
    Run all pending migrations in order.
    
    Returns:
        Dict[str, Any]: Result summary of migration execution
    """
    results = {
        'success': True,
        'applied_migrations': [],
        'errors': []
    }
    
    try:
        migration_files = get_migration_files()
        
        for migration_file in migration_files:
            if not is_migration_applied(migration_file):
                logger.info(f"Running migration: {migration_file}")
                # Import and run migration logic would go here
                mark_migration_applied(migration_file)
                results['applied_migrations'].append(migration_file)
                
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        results['success'] = False
        results['errors'].append(str(e))
    
    return results