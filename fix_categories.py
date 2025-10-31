#!/usr/bin/env python3
"""
Fix categories with corrupted emoji icons
"""

import logging
from pathlib import Path
import sys

# Add the backend directory to the path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from db import Database

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_categories():
    """Fix categories with proper Material Icons"""
    
    categories = [
        {'name': 'Infrastructure', 'description': 'Roads, bridges, public buildings, utilities', 'icon': 'engineering', 'color': '#FF6B35'},
        {'name': 'Transportation', 'description': 'Public transport, traffic, parking issues', 'icon': 'directions_bus', 'color': '#4ECDC4'},
        {'name': 'Environment', 'description': 'Pollution, waste management, green spaces', 'icon': 'eco', 'color': '#45B7D1'},
        {'name': 'Public Safety', 'description': 'Crime, emergency services, public security', 'icon': 'security', 'color': '#F7DC6F'},
        {'name': 'Health & Sanitation', 'description': 'Public health, cleanliness, sanitation', 'icon': 'local_hospital', 'color': '#BB8FCE'},
        {'name': 'Utilities', 'description': 'Water, electricity, gas, internet services', 'icon': 'electrical_services', 'color': '#58D68D'},
        {'name': 'Education', 'description': 'Schools, libraries, educational facilities', 'icon': 'school', 'color': '#F8C471'},
        {'name': 'Other', 'description': 'General complaints and suggestions', 'icon': 'more_horiz', 'color': '#85929E'}
    ]
    
    connection = None
    cursor = None
    
    try:
        Database.connect()
        connection = Database.get_connection()
        cursor = connection.cursor()

        logger.info("Fixing categories with proper Material Icons...")

        for category in categories:
            cursor.execute('''
                UPDATE categories 
                SET icon_name = %s, color_code = %s, description = %s, updated_at = CURRENT_TIMESTAMP
                WHERE name = %s
            ''', (
                category['icon'],
                category['color'],
                category['description'],
                category['name']
            ))
            logger.info(f"✅ Fixed category: {category['name']}")

        connection.commit()
        logger.info("🎉 Categories fixed successfully!")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to fix categories: {e}")
        return False

    finally:
        try:
            if cursor:
                cursor.close()
            if connection:
                connection.close()  # Close directly, no pool return
        except Exception:
            pass
        Database.disconnect()

if __name__ == "__main__":
    logger.info("🔧 Starting category fix...")
    success = fix_categories()

    if success:
        logger.info("✅ Category fix completed successfully!")
    else:
        logger.error("❌ Category fix failed!")