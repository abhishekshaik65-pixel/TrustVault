TrustVault – Secure Document Management System

Project Overview

TrustVault is a web-based document management application that allows users to register, log in, upload, view, search, download and delete their documents securely.

The application uses user authentication and ownership-based access control to ensure that users can access only their own documents.

Key Features

- User registration and login
- JWT-based authentication
- Password hashing using PBKDF2-SHA256
- Secure document upload
- Unique filenames for uploaded files
- User-specific document listing
- Document search
- Document download
- Document deletion
- Ownership verification for document operations

Technology Stack

- Backend: Python, FastAPI
- Frontend: HTML, CSS, JavaScript
- Database: SQLite
- Authentication: JWT
- Password Security: PBKDF2-SHA256

Project Structure

TrustVault/
│
├── backend/
│   ├── main.py
│   └── database.py
│
├── frontend/
│   ├── index.html
│   └── style.css
│
├── uploads/
├── trustvault.db
└── README.md

How to Run

1. Install dependencies

py -m pip install -r requirements.txt

2. Open the backend folder

cd backend

3. Set the secret key in PowerShell

$env:SECRET_KEY = (py -c "import secrets; print(secrets.token_urlsafe(32))")

4. Start the backend

py -m uvicorn main:app --reload

5. Open the frontend

Open "frontend/index.html" in your browser.

6. API documentation

After starting the backend, visit:

http://127.0.0.1:8000/docs

Security Notes

- Passwords are hashed before storage.
- Protected API endpoints require authentication.
- Document ownership is checked during document operations.
- Uploaded files are assigned unique filenames.
- Keep the JWT secret key private.

Project Objective

To provide a simple, authenticated document management platform with user-specific access control and document handling capabilities.