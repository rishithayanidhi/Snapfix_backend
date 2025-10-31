# main.py - Production Ready SnapFix Backend API

import os
import uuid
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query, Path as PathParam, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, validator
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    print("⚠️ slowapi not available - rate limiting disabled")

from db import Database, UserService, AuthService, CategoryService, ComplaintService, AttachmentService

# ==========================================================
# Configuration & Environment Setup
# ==========================================================
from dotenv import load_dotenv
load_dotenv()

# Environment variables with defaults
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "10485760"))  # 10MB
ALLOWED_FILE_TYPES = os.getenv("ALLOWED_FILE_TYPES", "image/jpeg,image/png,image/gif,image/webp,application/pdf").split(",")
UPLOAD_PATH = os.getenv("UPLOAD_PATH", "uploads")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@snapfix.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123!")
SUPER_ADMIN_KEY = os.getenv("SUPER_ADMIN_KEY", "super-admin-secret-2024")

# ==========================================================
# Directory Setup
# ==========================================================
BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
UPLOADS_DIR = BASE_DIR / UPLOAD_PATH
COMPLAINTS_DIR = UPLOADS_DIR / "complaints"

for folder in (LOGS_DIR, UPLOADS_DIR, COMPLAINTS_DIR):
    folder.mkdir(parents=True, exist_ok=True)

# ==========================================================
# Logging Configuration
# ==========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("main")

# ==========================================================
# Rate Limiting Setup
# ==========================================================
if RATE_LIMITING_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)
    
    def rate_limit(limit_string):
        return limiter.limit(limit_string)
else:
    # Fallback decorator when rate limiting is not available
    def rate_limit(limit_string):
        def decorator(func):
            return func
        return decorator
    
    limiter = None

# ==========================================================
# App Initialization
# ==========================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting SnapFix API...")
    try:
        Database.connect()
        logger.info("✅ Database connected successfully")
        
        # Create admin user if not exists
        try:
            existing_admin = UserService.get_user_by_email(ADMIN_EMAIL)
            if not existing_admin:
                UserService.create_user("Admin User", ADMIN_EMAIL, ADMIN_PASSWORD)
                logger.info(f"✅ Admin user created: {ADMIN_EMAIL}")
        except Exception as e:
            logger.warning(f"⚠️ Admin user creation failed: {e}")
            
    except Exception as e:
        logger.exception("❌ Startup failed")
        raise
    yield
    logger.info("📤 Shutting down SnapFix API...")
    try:
        Database.disconnect()
        logger.info("✅ Database disconnected successfully")
    except Exception as e:
        logger.exception("❌ Shutdown error")

app = FastAPI(
    title="SnapFix Backend API",
    description="Production-ready API for the SnapFix Flutter complaint management system",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
)

# ==========================================================
# Security & CORS & Middleware
# ==========================================================
security = HTTPBearer()

# Rate limiting middleware (if available)
if RATE_LIMITING_AVAILABLE and limiter:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

# Trusted hosts (production security)
if not DEBUG:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# CORS Configuration
allow_origins = os.getenv("ALLOW_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in allow_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    if os.getenv("ENABLE_SECURITY_HEADERS", "true").lower() == "true":
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if os.getenv("FORCE_HTTPS", "false").lower() == "true":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ==========================================================
# Enhanced Pydantic Models
# ==========================================================
class UserCreate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name of the user")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=6, max_length=128, description="Password (minimum 6 characters)")

class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")

class UserResponse(BaseModel):
    id: str
    full_name: str
    email: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: UserResponse

class LocationData(BaseModel):
    latitude: Optional[float] = Field(None, ge=-90, le=90, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, ge=-180, le=180, description="Longitude coordinate")
    address: Optional[str] = Field(None, max_length=500, description="Human readable address")
    accuracy: Optional[float] = Field(None, ge=0, description="GPS accuracy in meters")

class ComplaintCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Name of person filing complaint")
    email: EmailStr = Field(..., description="Contact email address")
    category: str = Field(..., min_length=1, max_length=50, description="Complaint category")
    title: Optional[str] = Field(None, max_length=200, description="Brief title for the complaint")
    description: str = Field(..., min_length=10, max_length=2000, description="Detailed description")
    location_data: Optional[LocationData] = Field(None, description="Location information")

    @validator('category')
    def validate_category(cls, v):
        allowed_categories = ['Roads', 'Garbage', 'Electricity', 'Water', 'Others']
        if v not in allowed_categories:
            raise ValueError(f'Category must be one of: {", ".join(allowed_categories)}')
        return v

class ComplaintStatusUpdate(BaseModel):
    status: str = Field(..., description="New status for the complaint")
    
    @validator('status')
    def validate_status(cls, v):
        allowed_statuses = ['Pending', 'In Progress', 'Approved', 'Rejected', 'Resolved']
        if v not in allowed_statuses:
            raise ValueError(f'Status must be one of: {", ".join(allowed_statuses)}')
        return v

class SimpleComplaintResponse(BaseModel):
    id: str
    name: str
    email: str
    category: str
    title: Optional[str]
    description: str
    location_address: Optional[str]
    location_latitude: Optional[float]
    location_longitude: Optional[float]
    photo_filename: Optional[str]
    status: str
    created_at: str

class CategoryResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    icon: Optional[str]
    color: Optional[str]
    created_at: Optional[str]

class AttachmentResponse(BaseModel):
    id: str
    complaint_id: str
    file_name: str
    file_path: str
    file_type: Optional[str]
    file_size: Optional[int]
    uploaded_by: Optional[str]
    created_at: Optional[str]

class AdminLoginRequest(BaseModel):
    email: EmailStr = Field(..., description="Admin email address")
    password: str = Field(..., description="Admin password")
    admin_key: Optional[str] = Field(None, description="Super admin key for elevated access")

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int

class ErrorResponse(BaseModel):
    error: str
    message: str
    timestamp: datetime

# ==========================================================
# Authentication Dependencies & Utilities
# ==========================================================
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user from JWT token"""
    try:
        token = credentials.credentials
        payload = AuthService.decode_token(token)
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = UserService.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current admin user - must be admin email"""
    user = get_current_user(credentials)
    if user.get("email") != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def validate_file_upload(file: UploadFile) -> bool:
    """Validate uploaded file size and type"""
    if file.size and file.size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE // 1024 // 1024}MB"
        )
    
    if file.content_type not in ALLOWED_FILE_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"File type not allowed. Allowed types: {', '.join(ALLOWED_FILE_TYPES)}"
        )
    
    return True

def create_error_response(error: str, message: str) -> JSONResponse:
    """Create standardized error response"""
    return JSONResponse(
        status_code=400,
        content={
            "error": error,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ==========================================================
# Health & System Endpoints
# ==========================================================
@app.get("/health", tags=["System"])
@rate_limit("10/minute")
def health_check(request: Request):
    """System health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "environment": ENVIRONMENT
    }

@app.get("/", tags=["System"])
def root():
    """API root endpoint with available routes"""
    return {
        "service": "SnapFix Backend API",
        "version": "1.0.0",
        "status": "running",
        "environment": ENVIRONMENT,
        "documentation": "/docs" if DEBUG else "Contact admin for API documentation",
        "endpoints": {
            "system": {
                "health": "/health",
                "root": "/"
            },
            "auth": {
                "register": "/auth/register",
                "login": "/auth/login",
                "profile": "/auth/profile"
            },
            "complaints": {
                "create_public": "/api/complaints/public",
                "list": "/api/complaints",
                "get_by_id": "/api/complaints/{id}",
                "get_by_email": "/api/complaints/by-email/{email}",
                "upload_attachment": "/api/public/complaints/{id}/attachments"
            },
            "categories": {
                "list": "/api/categories"
            },
            "admin": {
                "login": "/admin/login",
                "complaints": "/admin/complaints",
                "users": "/admin/users"
            }
        }
    }

# ==========================================================
# Authentication Routes
# ==========================================================
@app.post("/auth/register", response_model=TokenResponse, status_code=201, tags=["Authentication"])
@rate_limit("5/minute")
def register(request: Request, user_data: UserCreate):
    """Register a new user account"""
    try:
        user = UserService.create_user(user_data.full_name, user_data.email, user_data.password)
        token_data = AuthService.create_access_token(user_id=str(user["id"]), email=user["email"])
        return TokenResponse(**token_data, user=UserResponse(**user))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
@rate_limit("10/minute")
def login(request: Request, user_data: UserLogin):
    """Login with email and password"""
    try:
        user = UserService.authenticate_user(user_data.email, user_data.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token_data = AuthService.create_access_token(user_id=str(user["id"]), email=user["email"])
        return TokenResponse(**token_data, user=UserResponse(**user))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/auth/profile", response_model=UserResponse, tags=["Authentication"])
@rate_limit("30/minute")
def get_profile(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user profile"""
    return UserResponse(**current_user)

@app.post("/admin/login", response_model=TokenResponse, tags=["Admin"])
@rate_limit("3/minute")
def admin_login(request: Request, admin_data: AdminLoginRequest):
    """Admin login endpoint"""
    try:
        # Verify admin credentials
        if admin_data.email != ADMIN_EMAIL:
            raise HTTPException(status_code=401, detail="Invalid admin credentials")
        
        user = UserService.authenticate_user(admin_data.email, admin_data.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid admin credentials")
        
        # Check super admin key if provided
        if admin_data.admin_key and admin_data.admin_key != SUPER_ADMIN_KEY:
            raise HTTPException(status_code=401, detail="Invalid super admin key")
        
        token_data = AuthService.create_access_token(user_id=str(user["id"]), email=user["email"])
        return TokenResponse(**token_data, user=UserResponse(**user))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        raise HTTPException(status_code=500, detail="Admin login failed")

# ==========================================================
# Complaint Management Routes
# ==========================================================
@app.get("/api/categories", response_model=List[CategoryResponse], tags=["Categories"])
@rate_limit("60/minute")
def get_categories(request: Request):
    """Get all available complaint categories"""
    try:
        categories = CategoryService.get_all_categories()
        for c in categories:
            if isinstance(c.get("created_at"), datetime):
                c["created_at"] = c["created_at"].isoformat()
        return [CategoryResponse(**c) for c in categories]
    except Exception as e:
        logger.error(f"Get categories error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve categories")

@app.post("/api/complaints/public", response_model=SimpleComplaintResponse, status_code=201, tags=["Complaints"])
@rate_limit("10/minute")
def create_public_complaint(request: Request, req: ComplaintCreateRequest):
    """Create a new public complaint (no authentication required)"""
    try:
        location_data = req.location_data.dict() if req.location_data else None
        complaint = ComplaintService.create_simple_complaint(
            name=req.name,
            email=req.email,
            category=req.category,
            title=req.title,
            description=req.description,
            location_data=location_data,
            photo_data=None,
        )
        return SimpleComplaintResponse(**complaint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Create complaint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create complaint")

@app.get("/api/complaints", response_model=List[SimpleComplaintResponse], tags=["Complaints"])
@rate_limit("30/minute")
def list_complaints(
    request: Request,
    limit: int = Query(50, ge=1, le=100, description="Number of complaints to return"),
    offset: int = Query(0, ge=0, description="Number of complaints to skip"),
    status: Optional[str] = Query(None, description="Filter by status")
):
    """Get list of complaints with pagination and optional status filter"""
    try:
        complaints = ComplaintService.get_simple_complaints(limit, offset, status)
        return [SimpleComplaintResponse(**c) for c in complaints]
    except Exception as e:
        logger.error(f"List complaints error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve complaints")

@app.get("/api/complaints/{complaint_id}", response_model=SimpleComplaintResponse, tags=["Complaints"])
@rate_limit("60/minute")
def get_complaint_by_id(request: Request, complaint_id: str = PathParam(..., description="Complaint ID")):
    """Get a specific complaint by ID"""
    try:
        complaint = ComplaintService.get_simple_complaint_by_id(complaint_id)
        if not complaint:
            raise HTTPException(status_code=404, detail="Complaint not found")
        return SimpleComplaintResponse(**complaint)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get complaint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve complaint")

@app.get("/api/complaints/by-email/{email}", response_model=List[SimpleComplaintResponse], tags=["Complaints"])
@rate_limit("20/minute")
def get_complaints_by_email(request: Request, email: EmailStr = PathParam(..., description="Email address")):
    """Get all complaints submitted by a specific email address"""
    try:
        complaints = ComplaintService.get_complaints_by_email(email)
        return [SimpleComplaintResponse(**c) for c in complaints]
    except Exception as e:
        logger.error(f"Get complaints by email error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve complaints")

# ==========================================================
# File Upload & Attachment Routes
# ==========================================================
@app.post("/api/public/complaints/{complaint_id}/attachments", response_model=AttachmentResponse, tags=["Attachments"])
@rate_limit("5/minute")
async def upload_attachment(
    request: Request,
    complaint_id: str = PathParam(..., description="Complaint ID"),
    file: UploadFile = File(..., description="File to upload")
):
    """Upload an attachment to a specific complaint"""
    try:
        # Validate complaint exists
        complaint = ComplaintService.get_simple_complaint_by_id(complaint_id)
        if not complaint:
            raise HTTPException(status_code=404, detail="Complaint not found")

        # Validate file
        validate_file_upload(file)

        # Generate unique filename
        file_ext = Path(file.filename).suffix.lower()
        if not file_ext:
            file_ext = ".jpg"  # Default extension
        unique_name = f"{uuid.uuid4().hex}{file_ext}"
        dest = COMPLAINTS_DIR / unique_name

        # Save file
        try:
            with dest.open("wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
        except Exception as e:
            logger.error(f"File save error: {e}")
            raise HTTPException(status_code=500, detail="File upload failed")

        # Create attachment record
        attachment = AttachmentService.create_attachment(
            complaint_id=complaint_id,
            file_name=file.filename,
            file_path=str(dest.relative_to(BASE_DIR)),
            file_type=file.content_type,
            file_size=dest.stat().st_size,
            uploaded_by=None,
        )
        
        if isinstance(attachment.get("created_at"), datetime):
            attachment["created_at"] = attachment["created_at"].isoformat()

        return AttachmentResponse(**attachment)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload attachment error: {e}")
        raise HTTPException(status_code=500, detail="File upload failed")

@app.get("/uploads/complaints/{filename}", tags=["Attachments"])
@rate_limit("100/minute")
def serve_complaint_file(request: Request, filename: str = PathParam(..., description="Filename to serve")):
    """Serve uploaded complaint attachment files"""
    try:
        # Security: validate filename (prevent directory traversal)
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        file_path = COMPLAINTS_DIR / filename
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        return FileResponse(
            str(file_path),
            media_type="application/octet-stream",
            filename=filename
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Serve file error: {e}")
        raise HTTPException(status_code=500, detail="File serving failed")

# ==========================================================
# Admin Routes
# ==========================================================
@app.get("/admin/complaints", response_model=List[SimpleComplaintResponse], tags=["Admin"])
@rate_limit("100/minute")
def admin_list_complaints(
    request: Request,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    limit: int = Query(100, ge=1, le=500, description="Number of complaints to return"),
    offset: int = Query(0, ge=0, description="Number of complaints to skip"),
    status: Optional[str] = Query(None, description="Filter by status")
):
    """Admin endpoint to list all complaints with extended limits"""
    try:
        complaints = ComplaintService.get_simple_complaints(limit, offset, status)
        return [SimpleComplaintResponse(**c) for c in complaints]
    except Exception as e:
        logger.error(f"Admin list complaints error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve complaints")

@app.patch("/admin/complaints/{complaint_id}/status", response_model=SimpleComplaintResponse, tags=["Admin"])
@rate_limit("60/minute")
def admin_update_complaint_status(
    request: Request,
    complaint_id: str = PathParam(..., description="Complaint ID"),
    status_update: ComplaintStatusUpdate = ...,
    admin_user: Dict[str, Any] = Depends(get_admin_user)
):
    """Admin endpoint to update complaint status"""
    try:
        updated_complaint = ComplaintService.update_complaint_status(complaint_id, status_update.status)
        if not updated_complaint:
            raise HTTPException(status_code=404, detail="Complaint not found")
        return SimpleComplaintResponse(**updated_complaint)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin update status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update complaint status")

@app.get("/admin/users", response_model=List[UserResponse], tags=["Admin"])
@rate_limit("30/minute")
def admin_list_users(
    request: Request,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    limit: int = Query(50, ge=1, le=200, description="Number of users to return"),
    offset: int = Query(0, ge=0, description="Number of users to skip")
):
    """Admin endpoint to list all users"""
    try:
        # This would need to be implemented in UserService
        # For now, return basic info
        return [UserResponse(**admin_user)]
    except Exception as e:
        logger.error(f"Admin list users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")

@app.get("/admin/stats", tags=["Admin"])
@rate_limit("30/minute")
def admin_get_stats(
    request: Request,
    admin_user: Dict[str, Any] = Depends(get_admin_user)
):
    """Admin endpoint to get system statistics"""
    try:
        # Get basic stats
        all_complaints = ComplaintService.get_simple_complaints(1000, 0)  # Get large sample
        total_complaints = len(all_complaints)
        
        status_counts = {}
        for complaint in all_complaints:
            status = complaint.get('status', 'Unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_complaints": total_complaints,
            "status_breakdown": status_counts,
            "recent_complaints": len([c for c in all_complaints[:10]]),  # Last 10
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")

# ==========================================================
# Static Files & Error Handlers
# ==========================================================
# Mount static files for serving uploads
app.mount("/static", StaticFiles(directory=str(UPLOADS_DIR)), name="static")

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ==========================================================
# Development Entry Point
# ==========================================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    logger.info(f"🚀 Starting SnapFix API on {host}:{port}")
    logger.info(f"📊 Environment: {ENVIRONMENT}")
    logger.info(f"🐛 Debug mode: {DEBUG}")
    logger.info(f"📁 Upload directory: {UPLOADS_DIR}")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=DEBUG,
        log_level="info" if not DEBUG else "debug"
    )

