from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
import uuid 
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database import create_tables, get_connection
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import shutil
import os
import hashlib
import secrets
import hmac
from fastapi import Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Generate JWT Token
def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    token = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token
def hash_password(password: str):
    salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        600000
    ).hex()

    return f"pbkdf2_sha256${salt}${hashed}"


def verify_password(password: str, stored_password: str):
    try:
        algorithm, salt, stored_hash = stored_password.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            600000
        ).hex()

        return hmac.compare_digest(new_hash, stored_hash)

    except ValueError:
        return False
app = FastAPI(title="TrustVault API")
# JWT Authentication
security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("user_id")

        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, role FROM users WHERE id=?",
        (user_id,)
    )

    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return dict(user)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

create_tables()
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/")
def home():
    return {"message": "TrustVault API is running"}

@app.post("/login")
def login(data: LoginRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (data.username,)
    )

    user = cursor.fetchone()

    if not user:
        conn.close()
        return {"message": "Invalid username or password"}

    stored_password = user["password"]

    if stored_password.startswith("pbkdf2_sha256$"):
        valid = verify_password(
            data.password,
            stored_password
        )
    else:
        # Support existing accounts during migration
        valid = hmac.compare_digest(
            data.password,
            stored_password
        )

        if valid:
            cursor.execute(
                "UPDATE users SET password=? WHERE id=?",
                (hash_password(data.password), user["id"])
            )
            conn.commit()

    conn.close()

    if valid:
        access_token = create_access_token(
            data={
                "sub": user["username"],
                "user_id": user["id"],
                "role": user["role"]
            }
        )

        return {
            "message": "Login successful",
            "access_token": access_token,
            "token_type": "bearer"
        }

    return {"message": "Invalid username or password"}
@app.post("/register")
def register(data: LoginRequest):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (data.username,)
    )

    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return {"message": "Username already exists"}

    cursor.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (data.username, hash_password(data.password), "user")
    )

    conn.commit()
    conn.close()

    return {"message": "Registration successful"}
@app.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    owner_id = current_user["id"]
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE id=?",
        (owner_id,)
    )

    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    filename = str(uuid.uuid4()) + "_" + os.path.basename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    cursor.execute(
        "INSERT INTO documents (filename, owner_id) VALUES (?, ?)",
        (filename, owner_id)
    )

    conn.commit()
    conn.close()

    return {"message": "Document uploaded successfully"}
@app.get("/documents")
def get_documents(
    current_user: dict = Depends(get_current_user)
):
    owner_id = current_user["id"]

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM documents WHERE owner_id=?",
        (owner_id,)
    )

    documents = cursor.fetchall()
    conn.close()

    return {
        "documents": [dict(doc) for doc in documents]
    }
@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    current_user: dict = Depends(get_current_user)
):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        # Check document ownership
        cursor.execute(
            "SELECT filename FROM documents WHERE id=? AND owner_id=?",
            (document_id, current_user["id"])
        )

        document = cursor.fetchone()

        if not document:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )

        # Delete physical file
        file_path = os.path.join(
            UPLOAD_DIR,
            document["filename"]
        )

        if os.path.isfile(file_path):
            os.remove(file_path)

        # Delete database record
        cursor.execute(
            "DELETE FROM documents WHERE id=? AND owner_id=?",
            (document_id, current_user["id"])
        )

        conn.commit()

        return {
            "message": "Document deleted successfully"
        }

    finally:
        conn.close()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filename FROM documents WHERE id=?",
        (document_id,)
    )

    document = cursor.fetchone()

    if not document:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    file_path = os.path.join(UPLOAD_DIR, document["filename"])

    if os.path.exists(file_path):
        os.remove(file_path)

    cursor.execute(
        "DELETE FROM documents WHERE id=?",
        (document_id,)
    )

    conn.commit()
    conn.close()

    return {"message": "Document deleted successfully"}
@app.get("/download/{document_id}")
def download_document(
    document_id: int,
    current_user: dict = Depends(get_current_user)
):
    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT filename FROM documents WHERE id=? AND owner_id=?",
            (document_id, current_user["id"])
        )

        document = cursor.fetchone()

        if not document:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )

        file_path = os.path.join(
            UPLOAD_DIR,
            document["filename"]
        )

        if not os.path.isfile(file_path):
            raise HTTPException(
                status_code=404,
                detail="File not found"
            )

        return FileResponse(
            path=file_path,
            filename=document["filename"]
        )

    finally:
        conn.close()