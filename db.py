import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
import bcrypt
import jwt
import uuid
import logging
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "30"))

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Setup system_info logger
info_logger = logging.getLogger('system_info')
info_logger.setLevel(logging.INFO)
if not info_logger.handlers:
    info_handler = logging.FileHandler('logs/system_info.log')
    info_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    info_handler.setFormatter(info_formatter)
    info_logger.addHandler(info_handler)

# Setup system_error logger
error_logger = logging.getLogger('system_error')
error_logger.setLevel(logging.ERROR)
if not error_logger.handlers:
    error_handler = logging.FileHandler('logs/system_error.log')
    error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s')
    error_handler.setFormatter(error_formatter)
    error_logger.addHandler(error_handler)

# Setup app_info logger
app_info_logger = logging.getLogger('app_info')
app_info_logger.setLevel(logging.INFO)
if not app_info_logger.handlers:
    app_info_handler = logging.FileHandler('logs/app_info.log')
    app_info_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    app_info_handler.setFormatter(app_info_formatter)
    app_info_logger.addHandler(app_info_handler)

# Setup app_error logger
app_error_logger = logging.getLogger('app_error')
app_error_logger.setLevel(logging.ERROR)
if not app_error_logger.handlers:
    app_error_handler = logging.FileHandler('logs/app_error.log')
    app_error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s')
    app_error_handler.setFormatter(app_error_formatter)
    app_error_logger.addHandler(app_error_handler)

# Setup general logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Database:
    _pool: Optional[SimpleConnectionPool] = None

    @classmethod
    def connect(cls):
        """Initialize database connection pool"""
        if cls._pool is None:
            try:
                cls._pool = SimpleConnectionPool(
                    1, 20, DATABASE_URL
                )
                logger.info("✅ Database connection pool created successfully")
                info_logger.info("SYSTEM_INFO: Database connection pool initialized - Pool size: 1-20 connections")
                cls.init_tables()
            except Exception as e:
                logger.error(f"❌ Failed to connect to database: {e}")
                error_logger.error(f"SYSTEM_ERROR: Database connection failed - Error: {str(e)}")
                raise

    @classmethod
    def disconnect(cls):
        """Close database connection pool"""
        if cls._pool:
            cls._pool.closeall()
            cls._pool = None
            logger.info("📤 Database connection pool closed")
            info_logger.info("SYSTEM_INFO: Database connection pool closed successfully")

    @classmethod
    def get_connection(cls):
        """Get database connection from pool"""
        if cls._pool is None:
            cls.connect()
        return cls._pool.getconn()

    @classmethod
    def return_connection(cls, connection):
        """Return connection to pool"""
        cls._pool.putconn(connection)

    @classmethod
    def init_tables(cls):
        """Initialize database tables"""
        try:
            connection = cls.get_connection()
            cursor = connection.cursor()
            
            # Check if tables already exist
            cursor.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'complaints'
            """)
            
            if cursor.fetchone():
                logger.info("✅ Database tables already exist, skipping initialization")
                cursor.close()
                cls.return_connection(connection)
                return
            
            cursor.execute('''
                CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
                
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    full_name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
                
                -- Categories table
                CREATE TABLE IF NOT EXISTS categories (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    name VARCHAR(100) UNIQUE NOT NULL,
                    description TEXT,
                    icon_name VARCHAR(100),
                    color_code VARCHAR(7),
                    is_active BOOLEAN DEFAULT TRUE,
                    display_order INTEGER DEFAULT 0,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                
                -- Complaint attachments table
                CREATE TABLE IF NOT EXISTS complaint_attachments (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    complaint_id UUID REFERENCES complaints(id) ON DELETE CASCADE,
                    file_name VARCHAR(255) NOT NULL,
                    file_path VARCHAR(500) NOT NULL,
                    file_type VARCHAR(100),
                    file_size INTEGER,
                    uploaded_by UUID REFERENCES users(id),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                
                -- Simple complaints table for direct submissions (no authentication required)
                CREATE TABLE IF NOT EXISTS complaints (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    category VARCHAR(100) NOT NULL,
                    title VARCHAR(255),
                    description TEXT NOT NULL,
                    location_address TEXT,
                    location_latitude DECIMAL(10, 8),
                    location_longitude DECIMAL(11, 8),
                    location_accuracy DECIMAL(8, 2),
                    photo_filename VARCHAR(255),
                    photo_path VARCHAR(500),
                    photo_size INTEGER,
                    status VARCHAR(50) DEFAULT 'Pending' 
                        CHECK (status IN ('Pending', 'In Progress', 'Approved', 'Rejected')),
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                
                -- Index for complaints
                CREATE INDEX IF NOT EXISTS idx_complaints_email ON complaints(email);
                CREATE INDEX IF NOT EXISTS idx_complaints_category ON complaints(category);
                CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);
                CREATE INDEX IF NOT EXISTS idx_complaints_created_at ON complaints(created_at);
                CREATE INDEX IF NOT EXISTS idx_complaints_location ON complaints(location_latitude, location_longitude);
                
                -- Insert default categories
                INSERT INTO categories (name, description, icon_name, color_code) VALUES
                ('Roads', 'Road and traffic related issues', 'road_rounded', '#3B82F6'),
                ('Garbage', 'Waste management and cleanliness issues', 'delete_sweep_rounded', '#10B981'),
                ('Electricity', 'Power and electrical infrastructure issues', 'electrical_services_rounded', '#F59E0B'),
                ('Water', 'Water supply and drainage issues', 'water_drop_rounded', '#06B6D4'),
                ('Others', 'Other municipal and civic issues', 'more_horiz_rounded', '#8B5CF6')
                ON CONFLICT (name) DO NOTHING;
            ''')
            
            connection.commit()
            cursor.close()
            cls.return_connection(connection)
            logger.info("✅ Database tables initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize tables: {e}")
            raise

class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    @staticmethod
    def create_access_token(user_id: str, email: str) -> Dict[str, Any]:
        """Create JWT access token"""
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=JWT_EXPIRATION_MINUTES)
        
        payload = {
            "user_id": str(user_id),
            "email": email,
            "iat": now,
            "exp": expires_at,
            "type": "access"
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": JWT_EXPIRATION_MINUTES * 60
        }

    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        """Decode and verify JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")

class UserService:
    @staticmethod
    def create_user(full_name: str, email: str, password: str) -> Dict[str, Any]:
        """Create a new user"""
        logger.info(f"Creating user: {email}")
        info_logger.info(f"SYSTEM_INFO: User creation process started - Email: {email}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email.lower(),))
            existing_user = cursor.fetchone()
            
            if existing_user:
                logger.warning(f"User creation failed - email exists: {email}")
                error_logger.error(f"SYSTEM_ERROR: User creation failed - Email already exists: {email}")
                raise ValueError("Email already registered")
            
            # Hash password and create user
            password_hash = AuthService.hash_password(password)
            
            cursor.execute('''
                INSERT INTO users (full_name, email, password_hash)
                VALUES (%s, %s, %s)
                RETURNING id, full_name, email, is_active, created_at, updated_at
            ''', (full_name.strip(), email.lower(), password_hash))
            
            user = cursor.fetchone()
            connection.commit()
            
            logger.info(f"✅ User created successfully: {email}")
            info_logger.info(f"SYSTEM_INFO: User created successfully - UserID: {user['id']}, Email: {email}")
            return dict(user)
            
        except Exception as e:
            connection.rollback()
            error_logger.error(f"SYSTEM_ERROR: User creation database error - Email: {email}, Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)

    @staticmethod
    def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with email and password"""
        logger.info(f"Authentication attempt for: {email}")
        info_logger.info(f"SYSTEM_INFO: User authentication attempt - Email: {email}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT id, full_name, email, password_hash, is_active, created_at, updated_at
                FROM users 
                WHERE email = %s AND is_active = TRUE
            ''', (email.lower(),))
            
            user = cursor.fetchone()
            
            if not user or not AuthService.verify_password(password, user['password_hash']):
                logger.warning(f"❌ Authentication failed for: {email}")
                error_logger.error(f"SYSTEM_ERROR: Authentication failed - Invalid credentials for Email: {email}")
                return None
            
            logger.info(f"✅ Authentication successful for: {email}")
            info_logger.info(f"SYSTEM_INFO: Authentication successful - UserID: {user['id']}, Email: {email}")
            user_dict = dict(user)
            del user_dict['password_hash']  # Remove password hash from response
            return user_dict
            
        except Exception as e:
            error_logger.error(f"SYSTEM_ERROR: Authentication database error - Email: {email}, Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)

    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        app_info_logger.info(f"APP_INFO: Fetching user by ID - UserID: {user_id}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT id, full_name, email, is_active, created_at, updated_at
                FROM users 
                WHERE id = %s AND is_active = TRUE
            ''', (user_id,))
            
            user = cursor.fetchone()
            
            if user:
                app_info_logger.info(f"APP_INFO: User found successfully - UserID: {user_id}")
            else:
                app_info_logger.info(f"APP_INFO: User not found - UserID: {user_id}")
                
            return dict(user) if user else None
            
        except Exception as e:
            app_error_logger.error(f"APP_ERROR: Failed to fetch user by ID - UserID: {user_id}, Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)

    @staticmethod
    def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        app_info_logger.info(f"APP_INFO: Fetching user by email - Email: {email}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT id, full_name, email, is_active, created_at, updated_at
                FROM users 
                WHERE email = %s AND is_active = TRUE
            ''', (email.lower(),))
            
            user = cursor.fetchone()
            
            if user:
                app_info_logger.info(f"APP_INFO: User found by email - UserID: {user['id']}, Email: {email}")
            else:
                app_info_logger.info(f"APP_INFO: User not found by email - Email: {email}")
                
            return dict(user) if user else None
            
        except Exception as e:
            app_error_logger.error(f"APP_ERROR: Failed to fetch user by email - Email: {email}, Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)


# Complaint Management Services

class CategoryService:
    @staticmethod
    def get_all_categories() -> List[Dict[str, Any]]:
        """Get all active categories"""
        app_info_logger.info("APP_INFO: Fetching all active categories")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT id, name, description, icon_name as icon, color_code as color, created_at
                FROM categories 
                WHERE is_active = TRUE
                ORDER BY display_order, name
            ''')
            
            categories = cursor.fetchall()
            app_info_logger.info(f"APP_INFO: Retrieved {len(categories)} active categories")
            return [dict(category) for category in categories]
            
        except Exception as e:
            app_error_logger.error(f"APP_ERROR: Failed to fetch categories - Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)

    @staticmethod
    def get_category_by_name(name: str) -> Optional[Dict[str, Any]]:
        """Get category by name"""
        app_info_logger.info(f"APP_INFO: Fetching category by name - Name: {name}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT id, name, description, icon_name as icon, color_code as color, created_at
                FROM categories 
                WHERE name = %s AND is_active = TRUE
            ''', (name,))
            
            category = cursor.fetchone()
            
            if category:
                app_info_logger.info(f"APP_INFO: Category found - Name: {name}, ID: {category['id']}")
            else:
                app_info_logger.info(f"APP_INFO: Category not found - Name: {name}")
                
            return dict(category) if category else None
            
        except Exception as e:
            app_error_logger.error(f"APP_ERROR: Failed to fetch category by name - Name: {name}, Error: {str(e)}")
            raise e
            
        finally:
            cursor.close()
            Database.return_connection(connection)


class AuthenticatedComplaintService:
    @staticmethod
    def create_complaint(
        user_id: str,
        category: str,
        title: str,
        description: str,
        location_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a new complaint"""
        logger.info(f"Creating complaint for user: {user_id}")
        info_logger.info(f"SYSTEM_INFO: Complaint creation started - UserID: {user_id}, Category: {category}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            # Get category ID
            category_data = CategoryService.get_category_by_name(category)
            if not category_data:
                raise ValueError(f"Invalid category: {category}")
            
            # Extract location data
            location_address = None
            location_latitude = None
            location_longitude = None
            location_accuracy = None
            location_city = None
            location_state = None
            location_country = None
            location_postal_code = None
            
            if location_data:
                location_address = location_data.get('address')
                location_latitude = location_data.get('latitude')
                location_longitude = location_data.get('longitude')
                location_accuracy = location_data.get('accuracy')
                location_city = location_data.get('city')
                location_state = location_data.get('state')
                location_country = location_data.get('country')
                location_postal_code = location_data.get('postalCode')
            
            # Create complaint
            cursor.execute('''
                INSERT INTO complaints (
                    user_id, category_id, title, description,
                    location_address, location_latitude, location_longitude, location_accuracy,
                    location_city, location_state, location_country, location_postal_code
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, user_id, category_id, title, description, status,
                         location_address, location_latitude, location_longitude, location_accuracy,
                         location_city, location_state, location_country, location_postal_code,
                         created_at, updated_at
            ''', (
                user_id, category_data['id'], title, description,
                location_address, location_latitude, location_longitude, location_accuracy,
                location_city, location_state, location_country, location_postal_code
            ))
            
            complaint = cursor.fetchone()
            connection.commit()
            
            complaint_dict = dict(complaint)
            complaint_dict['category'] = category_data
            
            logger.info(f"✅ Complaint created successfully: {complaint_dict['id']}")
            info_logger.info(f"SYSTEM_INFO: Complaint created - ID: {complaint_dict['id']}, UserID: {user_id}")
            return complaint_dict
            
        except Exception as e:
            connection.rollback()
            error_logger.error(f"SYSTEM_ERROR: Complaint creation failed - UserID: {user_id}, Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)

    @staticmethod
    def get_user_complaints(user_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get complaints for a user"""
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT c.id, c.user_id, c.title, c.description, c.status,
                       c.location_address, c.location_latitude, c.location_longitude,
                       c.location_city, c.location_state, c.location_country,
                       c.created_at, c.updated_at,
                       cat.name as category_name, cat.description as category_description,
                       cat.icon_name as category_icon, cat.color_code as category_color
                FROM complaints c
                JOIN categories cat ON c.category_id = cat.id
                WHERE c.user_id = %s AND c.is_active = TRUE
                ORDER BY c.created_at DESC
                LIMIT %s OFFSET %s
            ''', (user_id, limit, offset))
            
            complaints = cursor.fetchall()
            
            result = []
            for complaint in complaints:
                complaint_dict = dict(complaint)
                complaint_dict['category'] = {
                    'name': complaint_dict.pop('category_name'),
                    'description': complaint_dict.pop('category_description'),
                    'icon': complaint_dict.pop('category_icon'),
                    'color': complaint_dict.pop('category_color')
                }
                result.append(complaint_dict)
            
            return result
            
        finally:
            cursor.close()
            Database.return_connection(connection)

    @staticmethod
    def get_complaint_by_id(complaint_id: str, user_id: str = None) -> Optional[Dict[str, Any]]:
        """Get complaint by ID"""
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            query = '''
                SELECT c.id, c.user_id, c.title, c.description, c.status,
                       c.location_address, c.location_latitude, c.location_longitude,
                       c.location_city, c.location_state, c.location_country,
                       c.created_at, c.updated_at,
                       cat.name as category_name, cat.description as category_description,
                       cat.icon_name as category_icon, cat.color_code as category_color,
                       u.full_name as user_name, u.email as user_email
                FROM complaints c
                JOIN categories cat ON c.category_id = cat.id
                JOIN users u ON c.user_id = u.id
                WHERE c.id = %s AND c.is_active = TRUE
            '''
            params = [complaint_id]
            
            if user_id:
                query += ' AND c.user_id = %s'
                params.append(user_id)
            
            cursor.execute(query, params)
            complaint = cursor.fetchone()
            
            if not complaint:
                return None
            
            complaint_dict = dict(complaint)
            complaint_dict['category'] = {
                'name': complaint_dict.pop('category_name'),
                'description': complaint_dict.pop('category_description'),
                'icon': complaint_dict.pop('category_icon'),
                'color': complaint_dict.pop('category_color')
            }
            complaint_dict['user'] = {
                'name': complaint_dict.pop('user_name'),
                'email': complaint_dict.pop('user_email')
            }
            
            return complaint_dict
            
        finally:
            cursor.close()
            Database.return_connection(connection)


class AttachmentService:
    @staticmethod
    def create_attachment(
        complaint_id: str,
        file_name: str,
        file_path: str,
        file_type: str,
        file_size: int,
        uploaded_by: str
    ) -> Dict[str, Any]:
        """Create a new attachment"""
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                INSERT INTO complaint_attachments (
                    complaint_id, file_name, file_path, file_type, file_size, uploaded_by
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, complaint_id, file_name, file_path, file_type, file_size, created_at
            ''', (complaint_id, file_name, file_path, file_type, file_size, uploaded_by))
            
            attachment = cursor.fetchone()
            connection.commit()
            
            logger.info(f"✅ Attachment created successfully: {attachment['id']}")
            return dict(attachment)
            
        except Exception as e:
            connection.rollback()
            error_logger.error(f"SYSTEM_ERROR: Attachment creation failed - Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)

    @staticmethod
    def get_complaint_attachments(complaint_id: str) -> List[Dict[str, Any]]:
        """Get all attachments for a complaint"""
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT id, complaint_id, file_name, file_path, file_type, file_size, created_at
                FROM complaint_attachments
                WHERE complaint_id = %s
                ORDER BY created_at DESC
            ''', (complaint_id,))
            
            attachments = cursor.fetchall()
            return [dict(attachment) for attachment in attachments]
            
        finally:
            cursor.close()
            Database.return_connection(connection)


class ComplaintService:
    """Service for handling simple complaints (no authentication required)"""
    
    @staticmethod
    def create_simple_complaint(
        name: str,
        email: str, 
        category: str,
        description: str,
        title: Optional[str] = None,
        location_data: Optional[Dict[str, Any]] = None,
        photo_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a simple complaint with basic validation"""
        
        app_info_logger.info(f"APP_INFO: Creating new complaint - Name: {name}, Email: {email}, Category: {category}")
        
        # Basic validation
        if not name or not name.strip():
            app_error_logger.error(f"APP_ERROR: Complaint creation failed - Name is required for Email: {email}")
            raise ValueError("Name is required")
        if not email or not email.strip():
            app_error_logger.error("APP_ERROR: Complaint creation failed - Email is required")
            raise ValueError("Email is required")
        if not category or not category.strip():
            app_error_logger.error(f"APP_ERROR: Complaint creation failed - Category is required for Email: {email}")
            raise ValueError("Category is required")
        if not description or not description.strip():
            app_error_logger.error(f"APP_ERROR: Complaint creation failed - Description is required for Email: {email}")
            raise ValueError("Description is required")
        
        # Ensure title is not None
        if title is None or not title.strip():
            title = f"{category.strip()} Issue"

        # Ensure title is not None
        if title is None or not title.strip():
            title = f"{category.strip()} Issue"
        
        # Ensure title is not None
        if title is None or not title.strip():
            title = f"{category.strip()} Issue"
        
        # Ensure title is not None
        if title is None or not title.strip():
            title = f"{category.strip()} Issue"
            
        # Email format validation (basic)
        if '@' not in email or '.' not in email:
            app_error_logger.error(f"APP_ERROR: Complaint creation failed - Invalid email format: {email}")
            raise ValueError("Please provide a valid email address")
            
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            # Extract location data if provided
            location_address = None
            location_latitude = None
            location_longitude = None
            location_accuracy = None
            
            if location_data:
                location_address = location_data.get('address')
                location_latitude = location_data.get('latitude')
                location_longitude = location_data.get('longitude') 
                location_accuracy = location_data.get('accuracy')
            
            # Extract photo data if provided
            photo_filename = None
            photo_path = None
            photo_size = None
            
            if photo_data:
                photo_filename = photo_data.get('filename')
                photo_path = photo_data.get('path')
                photo_size = photo_data.get('size')
            
            # Insert the complaint
            app_info_logger.info(f"APP_INFO: Inserting complaint into database - Email: {email}")
            cursor.execute('''
                INSERT INTO complaints (
                    name, email, category, title, description,
                    location_address, location_latitude, location_longitude, location_accuracy,
                    photo_filename, photo_path, photo_size
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, name, email, category, title, description, 
                         location_address, location_latitude, location_longitude,
                         photo_filename, status, created_at
            ''', (
                name.strip(), email.strip(), category.strip(), title, description.strip(),
                location_address, location_latitude, location_longitude, location_accuracy,
                photo_filename, photo_path, photo_size
            ))
            
            complaint = cursor.fetchone()
            connection.commit()
            
            logger.info(f"✅ Complaint created successfully: {complaint['id']}")
            info_logger.info(f"SYSTEM_INFO: Complaint created - ID: {complaint['id']}, Email: {email}")
            app_info_logger.info(f"APP_INFO: Complaint created successfully - ID: {complaint['id']}, Name: {name}, Email: {email}")
            
            # Convert datetime fields to strings for API response
            result = dict(complaint)
            if result.get('created_at'):
                result['created_at'] = result['created_at'].isoformat()
            if result.get('updated_at'):
                result['updated_at'] = result['updated_at'].isoformat()
            
            return result
            
        except Exception as e:
            connection.rollback()
            logger.error(f"❌ Complaint creation failed: {e}")
            error_logger.error(f"SYSTEM_ERROR: Complaint creation failed - Email: {email}, Error: {str(e)}")
            app_error_logger.error(f"APP_ERROR: Complaint creation database error - Email: {email}, Error: {str(e)}")
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)
    
    @staticmethod
    def get_simple_complaints(
        limit: int = 50, 
        offset: int = 0,
        status_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get complaints with pagination and optional status filter"""
        app_info_logger.info(f"APP_INFO: Fetching complaints - Limit: {limit}, Offset: {offset}, Status Filter: {status_filter}")
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            where_clause = "WHERE is_active = TRUE"
            params = []
            
            if status_filter:
                where_clause += " AND status = %s"
                params.append(status_filter)
            
            params.extend([limit, offset])
            
            cursor.execute(f'''
                SELECT id, name, email, category, title, description,
                       location_address, location_latitude, location_longitude,
                       photo_filename, status, created_at
                FROM complaints
                {where_clause}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            ''', params)
            
            complaints = cursor.fetchall()
            app_info_logger.info(f"APP_INFO: Retrieved {len(complaints)} complaints successfully")
            
            # Convert datetime fields to strings for API response
            results = []
            for complaint in complaints:
                result = dict(complaint)
                if result.get('created_at'):
                    result['created_at'] = result['created_at'].isoformat()
                if result.get('updated_at'):
                    result['updated_at'] = result['updated_at'].isoformat()
                results.append(result)
            
            return results
            
        except Exception as e:
            app_error_logger.error(f"APP_ERROR: Failed to fetch complaints - Limit: {limit}, Offset: {offset}, Error: {str(e)}")
            raise e
            
        finally:
            cursor.close()
            Database.return_connection(connection)
    
    @staticmethod
    def get_simple_complaint_by_id(complaint_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific complaint by ID"""
        app_info_logger.info(f"APP_INFO: Fetching complaint by ID - ComplaintID: {complaint_id}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute('''
                SELECT id, name, email, category, title, description,
                       location_address, location_latitude, location_longitude,
                       photo_filename, photo_path, photo_size, status, 
                       created_at, updated_at
                FROM complaints
                WHERE id = %s AND is_active = TRUE
            ''', (complaint_id,))
            
            complaint = cursor.fetchone()
            
            if complaint:
                app_info_logger.info(f"APP_INFO: Complaint found successfully - ComplaintID: {complaint_id}")
                # Convert datetime fields to strings for API response
                result = dict(complaint)
                if result.get('created_at'):
                    result['created_at'] = result['created_at'].isoformat()
                if result.get('updated_at'):
                    result['updated_at'] = result['updated_at'].isoformat()
                return result
            else:
                app_info_logger.info(f"APP_INFO: Complaint not found - ComplaintID: {complaint_id}")
                return None
            
        except Exception as e:
            app_error_logger.error(f"APP_ERROR: Failed to fetch complaint by ID - ComplaintID: {complaint_id}, Error: {str(e)}")
            
            # Handle UUID validation errors gracefully
            if "invalid input syntax for type uuid" in str(e):
                app_info_logger.info(f"APP_INFO: Invalid UUID format provided - ComplaintID: {complaint_id}")
                return None
            
            # Re-raise other unexpected errors
            raise e
        finally:
            cursor.close()
            Database.return_connection(connection)
    
    @staticmethod
    def update_complaint_status(complaint_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        """Update complaint status"""
        app_info_logger.info(f"APP_INFO: Updating complaint status - ComplaintID: {complaint_id}, New Status: {new_status}")
        
        connection = Database.get_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)
        
        try:
            # Update the complaint status
            cursor.execute('''
                UPDATE complaints 
                SET status = %s, updated_at = NOW()
                WHERE id = %s AND is_active = TRUE
                RETURNING id, name, email, category, title, description,
                         location_address, location_latitude, location_longitude,
                         photo_filename, photo_path, photo_size, status, 
                         created_at, updated_at
            ''', (new_status, complaint_id))
            
            updated_complaint = cursor.fetchone()
            connection.commit()
            
            if updated_complaint:
                app_info_logger.info(f"APP_INFO: Complaint status updated successfully - ComplaintID: {complaint_id}, Status: {new_status}")
                # Convert datetime fields to strings for API response
                result = dict(updated_complaint)
                if result.get('created_at'):
                    result['created_at'] = result['created_at'].isoformat()
                if result.get('updated_at'):
                    result['updated_at'] = result['updated_at'].isoformat()
                return result
            else:
                app_info_logger.info(f"APP_INFO: Complaint not found for status update - ComplaintID: {complaint_id}")
                return None
            
        except Exception as e:
            connection.rollback()
            app_error_logger.error(f"APP_ERROR: Failed to update complaint status - ComplaintID: {complaint_id}, Status: {new_status}, Error: {str(e)}")
            
            # Handle UUID validation errors gracefully
            if "invalid input syntax for type uuid" in str(e):
                app_info_logger.info(f"APP_INFO: Invalid UUID format provided for status update - ComplaintID: {complaint_id}")
                return None
            
            # Re-raise other unexpected errors
            raise e
            
        finally:
            cursor.close()
            Database.return_connection(connection)
