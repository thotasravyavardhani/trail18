# QuMail Secure Email Client

## Overview
QuMail is a quantum-secure email client with end-to-end encryption featuring:
- FastAPI Python backend with quantum cryptography (PQC)
- React TypeScript frontend with Tailwind CSS
- SQLite database with SQLAlchemy ORM
- Mock Key Manager for quantum key distribution
- Email service supporting IMAP/SMTP

## Project Architecture
### Backend (Port 8000)
- **Location**: `/backend/`
- **Tech Stack**: FastAPI, SQLAlchemy, SQLite, Cryptography
- **Main Entry**: `main.py` 
- **Features**: Authentication, email encryption/decryption, IMAP/SMTP integration

### Frontend (Port 5000) 
- **Location**: `/frontend/`
- **Tech Stack**: React 18, TypeScript, Tailwind CSS
- **Build Tool**: react-scripts
- **Features**: Login, inbox, compose, settings UI

## Recent Changes (Sept 19, 2025)
- **GitHub Import Setup**: Fresh GitHub clone successfully imported and configured for Replit environment
- **Dependencies**: All Python backend (uv sync) and Node.js frontend (npm install) dependencies installed and verified
- **Workflows**: Set up dual workflows (Frontend on port 5000, Backend on port 8000 via uv run)
- **Configuration**: Frontend properly configured with DANGEROUSLY_DISABLE_HOST_CHECK=true for Replit proxy
- **Database**: SQLite database initialized successfully with QuMail schema
- **Deployment**: Configured VM deployment with React build process and concurrent serving (backend:8000 + frontend:5000)
- **API Testing**: Backend API endpoints verified working (health check: healthy, KM mock status available)
- **Production Setup**: Frontend to backend proxy communication verified working
- **Status**: Application fully functional and ready for development/production use - Import Complete ✅

## Development Setup
- Backend runs on `localhost:8000`
- Frontend runs on `0.0.0.0:5000` with proxy to backend
- SQLite database: `backend/qumail.db`
- Logs: Backend uses structured JSON logging

## Deployment Configuration
- Target: VM (maintains backend state)
- Build: Frontend React build process
- Run: Concurrent backend Python + frontend static serve

## User Preferences
- Security-focused email application
- Quantum-secure cryptography emphasis
- Professional email client interface