#!/usr/bin/env python3
"""
Initialize sample categories for the Smart Complaint System
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

def init_sample_categories():
    """Initialize sample categories"""
    
    categories = [
        {'name': 'Infrastructure', 'description': 'Roads, bridges, public buildings, utilities', 'icon': '🏗️', 'color': '#FF6B35'},
        {'name': 'Transportation', 'description': 'Public transport, traffic, parking issues', 'icon': '🚌', 'color': '#4ECDC4'},
        {'name': 'Environment', 'description': 'Pollution, waste management, green spaces', 'icon': '🌿', 'color': '#45B7D1'},
        {'name': 'Public Safety', 'description': 'Crime, emergency services, public security', 'icon': '🚨', 'color': '#F7DC6F'},
        {'name': 'Health & Sanitation', 'description': 'Public health, cleanliness, sanitation', 'icon': '🏥', 'color': '#BB8FCE'},
        {'name': 'Utilities', 'description': 'Water, electricity, gas, internet services', 'icon': '⚡', 'color': '#58D68D'},
        {'name': 'Education', 'description': 'Schools, libraries, educational facilities', 'icon': '📚', 'color': '#F8C471'},
        {'name': 'Other', 'description': 'General complaints and suggestions', 'icon': '📝', 'color': '#85929E'}
    ]
    
    connection = None
    cursor = None
    
    try:
        Database.connect()
        connection = Database.get_connection()
        cursor = connection.cursor()

        # Check if categories exist
        cursor.execute("SELECT COUNT(*) FROM categories;")
        count = cursor.fetchone()[0]

        if count > 0:
            logger.info("✅ Categories already exist. Skipping initialization.")
            return True  # graceful skip

        logger.info("Initializing sample categories...")

        for category in categories:
            cursor.execute('''
                INSERT INTO categories (name, description, icon_name, color_code, is_active)
                VALUES (%s, %s, %s, %s, TRUE)
                ON CONFLICT (name) DO UPDATE SET
                    description = EXCLUDED.description,
                    icon_name = EXCLUDED.icon_name,
                    color_code = EXCLUDED.color_code,
                    updated_at = CURRENT_TIMESTAMP
            ''', (
                category['name'],
                category['description'],
                category['icon'],
                category['color']
            ))
            logger.info(f"✅ Added/Updated category: {category['name']}")

        connection.commit()
        logger.info("🎉 Sample categories initialized successfully!")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to initialize categories: {e}")
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
    logger.info("🚀 Starting category initialization...")
    success = init_sample_categories()

    if success:
        logger.info("✅ Category initialization completed successfully!")
    else:
        logger.error("❌ Category initialization failed!")
