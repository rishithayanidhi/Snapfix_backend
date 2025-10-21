from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
import uvicorn
import logging
import os
import uuid
import shutil
from datetime import datetime
from pathlib import Path
from db import Database, UserService, AuthService, CategoryService, ComplaintService, AttachmentService

# =====================================
# Setup Directories
# =====================================
for folder in ["logs", "uploads", "uploads/complaints"]:
    os.makedirs(folder, exist_ok=True)

# =====================================
# Logging Setup
# =====================================
info_logger = logging.getLogger('system_info')
info_logger.setLevel(logging.INFO)
if not info_logger.handlers:
    info_handler = logging.FileHandler('logs/system_info.log')
    info_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    info_handler.setFormatter(info_formatter)
    info_logger.addHandler(info_handler)

error_logger = logging.getLogger('system_error')
error_logger.setLevel(logging.ERROR)
if not error_logger.handlers:
    error_handler = logging.FileHandler('logs/system_error.log')
    error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s')
    error_handler.setFormatter(error_formatter)
    error_logger.addHandler(error_handler)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# =====================================
# Lifespan (startup/shutdown)
# =====================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting up authentication API...")
    try:
        Database.connect()
        logger.info("✅ Database connected successfully")
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise

    yield

    logger.info("📤 Shutting down authentication API...")
    try:
        Database.disconnect()
        logger.info("✅ Database disconnected successfully")
    except Exception as e:
        logger.error(f"❌ Shutdown failed: {e}")

# =====================================
# FastAPI App Initialization
# =====================================
app = FastAPI(
    title="Flutter Authentication API",
    description="A simple authentication API for Flutter applications",
    version="1.0.0",
    lifespan=lifespan
)

security = HTTPBearer()

# =====================================
# CORS Middleware
# =====================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://your-frontend-domain.com",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================
# Models
# =====================================
class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

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

class SimpleComplaintResponse(BaseModel):
    id: str
    name: str
    email: str
    category: str
    title: Optional[str] = None
    description: str
    location_address: Optional[str] = None
    location_latitude: Optional[float] = None
    location_longitude: Optional[float] = None
    photo_filename: Optional[str] = None
    status: str
    created_at: str

class CategoryResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None
    created_at: Optional[str] = None

class AttachmentResponse(BaseModel):
    id: str
    complaint_id: str
    file_name: str
    file_path: str
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    uploaded_by: Optional[str] = None
    created_at: Optional[str] = None

class LocationData(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    accuracy: Optional[float] = None

class ComplaintCreateRequest(BaseModel):
    name: str
    email: str
    category: str
    title: Optional[str] = None
    description: str
    location_data: Optional[LocationData] = None

# =====================================
# Authentication Utilities
# =====================================
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current user from JWT"""
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

# =====================================
# Health
# =====================================
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "service": "Flutter Authentication API"
    }

# =====================================
# Auth Routes
# =====================================
@app.post("/auth/register", response_model=TokenResponse, status_code=201)
def register(user_data: UserCreate):
    user = UserService.create_user(user_data.full_name, user_data.email, user_data.password)
    token_data = AuthService.create_access_token(user_id=str(user["id"]), email=user["email"])
    return TokenResponse(**token_data, user=UserResponse(**user))

@app.post("/auth/login", response_model=TokenResponse)
def login(user_credentials: UserLogin):
    user = UserService.authenticate_user(user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token_data = AuthService.create_access_token(user_id=str(user["id"]), email=user["email"])
    return TokenResponse(**token_data, user=UserResponse(**user))

@app.get("/auth/profile", response_model=UserResponse)
def get_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    return UserResponse(**current_user)

# =====================================
# Categories
# =====================================
@app.get("/api/categories", response_model=List[CategoryResponse])
def get_categories():
    categories = CategoryService.get_all_categories()
    return [CategoryResponse(**category) for category in categories]

# =====================================
# Public Complaints (JSON version)
# =====================================
@app.post("/api/complaints/public", response_model=SimpleComplaintResponse, status_code=201)
async def create_public_complaint(request: ComplaintCreateRequest):
    """Public complaint submission (JSON body)"""
    location_data = None
    if request.location_data:
        location_data = {
            'address': request.location_data.address,
            'latitude': request.location_data.latitude,
            'longitude': request.location_data.longitude,
            'accuracy': request.location_data.accuracy
        }
    title = request.title if request.title else f"{request.category} Issue"
    complaint = ComplaintService.create_simple_complaint(
        name=request.name,
        email=request.email,
        category=request.category,
        title=title,
        description=request.description,
        location_data=location_data,
        photo_data=None
    )
    return SimpleComplaintResponse(**complaint)

# =====================================
# Root
# =====================================
@app.get("/")
def root():
    return {
        "message": "Flutter Smart Complaint System API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "auth": {
                "register": "/auth/register",
                "login": "/auth/login",
                "profile": "/auth/profile"
            },
            "complaints": {
                "public_create": "/api/complaints/public",
                "categories": "/api/categories"
            }
        }
    }

# =====================================
# Uvicorn Local Launch (Render uses Gunicorn)
# =====================================
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
