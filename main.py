"""
FastAPI Web Application using MVC Pattern
Models: SQLAlchemy and Pydantic models with full validation
Views: FastAPI route handlers
Controllers: Business logic separated from route definitions
SQLAlchemy for ORM, JWT for authentication, and in-memory cache for performance
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, constr
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy import Column, Integer, String, Text, ForeignKey, select
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import hashlib
import time

# configs and setup

DATABASE_URL = "sqlite+aiosqlite:///./test.db"
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# async DB setup
engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# fastAPI app instance
app = FastAPI()

# CORS settings (wide open here for simplicity)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB Models


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    posts = relationship("Post", back_populates="owner")


class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="posts")


# create tables on startup
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# pydantic schemas


class UserCreate(BaseModel):
    email: EmailStr
    password: constr(min_length=6)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class PostCreate(BaseModel):
    text: constr(min_length=1, max_length=1024 * 1024)  # 1 MB


class PostDelete(BaseModel):
    postID: int


class TokenData(BaseModel):
    email: EmailStr
    user_id: int


# helpers & auth

security = HTTPBearer()
cached_posts = {}  # in-memory cache {user_id: {data: [...], time: timestamp}}


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# plain SHA-256 hashing (replace with bcrypt or something)
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# just compare SHA-256 hashes
def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed


# JWT creator
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# JWT decoder (throw 401 if token is off)
def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(email=payload.get("email"), user_id=payload.get("user_id"))
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


# pull user info from token (used by any endpoint that needs auth)
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    token_data = decode_token(credentials.credentials)
    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    return user


# routes


@app.post("/signup")
async def signup(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # prevent duplicate email signup
    result = await db.execute(select(User).where(User.email == user.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # create the user and issue token
    new_user = User(email=user.email, password_hash=hash_password(user.password))
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    token = create_access_token(
        {"email": new_user.email, "user_id": new_user.id},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"token": token}


@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == user.email))
    db_user = result.scalars().first()

    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(
        {"email": db_user.email, "user_id": db_user.id},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"token": token}


@app.post("/addpost")
async def add_post(
    post: PostCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # save the post
    new_post = Post(text=post.text, owner_id=current_user.id)
    db.add(new_post)
    await db.commit()
    await db.refresh(new_post)

    # invalidate cache
    cached_posts.pop(current_user.id, None)
    return {"postID": new_post.id}


@app.get("/getposts")
async def get_posts(
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    now = time.time()
    cache = cached_posts.get(current_user.id)

    # serve cached if fresh (less than 5 min old)
    if cache and now - cache["time"] < 300:
        return {"posts": cache["data"]}

    # fetch fresh posts
    result = await db.execute(select(Post).where(Post.owner_id == current_user.id))
    posts = result.scalars().all()
    output = [{"id": post.id, "text": post.text} for post in posts]

    # cache it
    cached_posts[current_user.id] = {"data": output, "time": now}
    return {"posts": output}


@app.delete("/deletepost")
async def delete_post(
    payload: PostDelete,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Check if post exists and belongs to user
    result = await db.execute(
        select(Post).where(Post.id == payload.postID, Post.owner_id == current_user.id)
    )
    post = result.scalars().first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Delete and invalidate cache
    await db.delete(post)
    await db.commit()
    cached_posts.pop(current_user.id, None)
    return {"detail": "Post deleted"}
