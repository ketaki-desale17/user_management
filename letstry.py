import os
import re
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy import create_engine, Column, Integer, String, TIMESTAMP, func, ForeignKey, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")
# Check if DATABASE_URL is None and raise an error if so
if DATABASE_URL is None:
    raise ValueError("DATABASE_URL environment variable is not set.")

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT secret key and algorithm
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 Password Bearer token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

from sqlalchemy import Column, Integer, String, TIMESTAMP, func

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    phone_number = Column(String, nullable=False)
    password = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())


    roles = relationship("UserRole", back_populates="user")


# Role model
class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String, unique=True, index=True)
    permissions = Column(Text)
    created_at = Column(TIMESTAMP, server_default=func.now())

    users = relationship("UserRole", back_populates="role")

# UserRole model
class UserRole(Base):
    __tablename__ = "user_roles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    role_id = Column(Integer, ForeignKey("roles.id"))
    assigned_at = Column(TIMESTAMP, server_default=func.now())

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")

# Create the tables
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the User Management System"}

# Pydantic models
class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    password: str
    role_id: int = None  # Optional field to assign a specific role

    @validator("phone_number")
    def validate_phone_number(cls, value):
        if not re.match(r'^\d{10}$', value):
            raise ValueError("Phone number must be exactly 10 digits.")
        return value

    @validator("password")
    def validate_password(cls, value):
        if (len(value) < 8 or
            not re.search(r'[A-Z]', value) or
            not re.search(r'[a-z]', value) or
            not re.search(r'[0-9]', value) or
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', value)):
            raise ValueError("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
        return value

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class RoleCreate(BaseModel):
    role_name: str
    permissions: str  # Permissions can be a JSON string or some other format

class UserRoleAssign(BaseModel):
    role_id: int

class UserRolesResponse(BaseModel):
    user_id: int
    roles: list[str]  # List of role names assigned to the user

# Function to create JWT
def create_access_token(data: dict, role: str, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "role": role})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Function to verify token and extract user details
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        role: str = payload.get("role")
        return {"email": email, "role": role}
    except JWTError:
        raise credentials_exception

# Helper function to check if a user has a specific role
def role_required(allowed_roles: list):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden")
        return current_user
    return role_checker

# User Registration Endpoint
@app.post("/register", response_model=Token)
def register(user: UserCreate):
    db = SessionLocal()
    try:
        hashed_password = pwd_context.hash(user.password)

        # Check if email or phone number already exists
        if db.query(User).filter((User.email == user.email) | (User.phone_number == user.phone_number)).first():
            raise HTTPException(status_code=400, detail="Email or Phone Number already registered")

        new_user = User(
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            phone_number=user.phone_number,
            password=hashed_password
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Assign the provided role, or default to "User" if no role is provided
        if user.role_id:
            role = db.query(Role).filter(Role.id == user.role_id).first()
            if not role:
                raise HTTPException(status_code=404, detail="Role not found")
        else:
            role = db.query(Role).filter(Role.role_name == "User").first()
            if not role:
                raise HTTPException(status_code=404, detail="Default 'User' role not found")

        user_role = UserRole(user_id=new_user.id, role_id=role.id)
        db.add(user_role)
        db.commit()

        # Generate token with the assigned role
        access_token = create_access_token(data={"sub": new_user.email}, role=role.role_name)
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        db.close()

# User Login Endpoint
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    try:
        user_db = db.query(User).filter(User.email == form_data.username).first()

        if not user_db:
            raise HTTPException(status_code=400, detail="Email not found")

        if not pwd_context.verify(form_data.password, user_db.password):
            raise HTTPException(status_code=400, detail="Invalid password")

        # Fetch user's role
        user_role = db.query(UserRole).filter(UserRole.user_id == user_db.id).first()
        role = db.query(Role.role_name).filter(Role.id == user_role.role_id).first()[0]

        # Create JWT
        access_token = create_access_token(data={"sub": user_db.email}, role=role)
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        db.close()

# Role Management Endpoints

# Create Role: Only Admin can create roles
@app.post("/roles", dependencies=[Depends(role_required(["Admin"]))])
def create_role(role: RoleCreate):
    db = SessionLocal()
    try:
        new_role = Role(role_name=role.role_name, permissions=role.permissions)
        db.add(new_role)
        db.commit()
        db.refresh(new_role)
        return {"message": "Role created successfully", "role_id": new_role.id}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
    finally:
        db.close()

# Assign Role: Admin can assign any role, Manager can assign 'User' role
@app.post("/users/{user_id}/roles", dependencies=[Depends(role_required(["Admin", "Manager"]))])
def assign_role(user_id: int, role_assign: UserRoleAssign, current_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        role = db.query(Role).filter(Role.id == role_assign.role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        # Check if Manager is trying to assign anything other than "User" role
        if current_user["role"] == "Manager" and role.role_name != "User":
            raise HTTPException(status_code=403, detail="Managers can only assign the 'User' role")

        user_role = UserRole(user_id=user_id, role_id=role_assign.role_id)
        db.add(user_role)
        db.commit()
        return {"message": "Role assigned successfully"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
    finally:
        db.close()

# Remove Role: Admin can remove any role, Manager can remove only 'User' role
@app.delete("/users/{user_id}/roles/{role_id}", dependencies=[Depends(role_required(["Admin", "Manager"]))])
def remove_role(user_id: int, role_id: int, current_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user_role = db.query(UserRole).filter(UserRole.user_id == user_id, UserRole.role_id == role_id).first()
        if not user_role:
            raise HTTPException(status_code=404, detail="Role not assigned to user")

        role = db.query(Role).filter(Role.id == role_id).first()

        # Check if Manager is trying to remove anything other than "User" role
        if current_user["role"] == "Manager" and role.role_name != "User":
            raise HTTPException(status_code=403, detail="Managers can only remove the 'User' role")

        db.delete(user_role)
        db.commit()
        return {"message": "Role removed successfully"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
    finally:
        db.close()

# Get User Roles: Anyone with a role can view their own roles
@app.get("/users/{user_id}/roles", response_model=UserRolesResponse, dependencies=[Depends(role_required(["User", "Manager", "Admin"]))])
def get_user_roles(user_id: int):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        roles = db.query(Role.role_name).join(UserRole, Role.id == UserRole.role_id).filter(UserRole.user_id == user_id).all()
        role_names = [role[0] for role in roles]
        return {"user_id": user.id, "roles": role_names}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        db.close()

# Get All Roles: Anyone can view available roles
@app.get("/roles", dependencies=[Depends(role_required(["User", "Manager", "Admin"]))])
def get_all_roles():
    db = SessionLocal()
    try:
        roles = db.query(Role).all()
        return {"roles": [{"id": role.id, "role_name": role.role_name, "permissions": role.permissions} for role in roles]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        db.close()

# Example for Admin-only access
@app.get("/admin", dependencies=[Depends(role_required(["Admin"]))])
def admin_only():
    return {"message": "This is an admin-only section."}

# Example for Manager-only access
@app.get("/manager", dependencies=[Depends(role_required(["Manager", "Admin"]))])
def manager_only():
    return {"message": "This section is accessible by managers and admins."}

# Example for User access to profile
@app.get("/profile", dependencies=[Depends(role_required(["User", "Manager", "Admin"]))])
def view_profile(current_user: dict = Depends(get_current_user)):
    return {"email": current_user["email"], "role": current_user["role"]}


