# Tatou - PDF Watermarking Platform

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Tatou is a comprehensive PDF watermarking platform designed for secure document distribution and leak detection. It provides multiple watermarking methods, RMAP (Robust Messaging Authentication Protocol) encrypted authentication, and advanced leak tracking capabilities.

> **⚠️ Security Warning**: This project is intended for **pedagogical use only** and intentionally contains security vulnerabilities. **Do not deploy on an open network or in production environments.**

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Development Setup](#development-setup)
  - [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Testing](#testing)
  - [Unit Tests](#unit-tests)
  - [Integration Tests](#integration-tests)
  - [Coverage Analysis](#coverage-analysis)
- [License](#license)

## Features

- 🔐 **Secure Authentication**: JWT-based authentication with RMAP encrypted protocol support
- 📄 **PDF Management**: Upload, store, and manage PDF documents
- 🎨 **Multiple Watermarking Methods**:
  - Add-after-EOF
  - Metadata watermarking
  - Multi-location robust advanced watermarking
  - PawStamp watermarking
  - Bash bridge append EOF
- 🔍 **Leak Detection**: Identify document leakers through watermark extraction
- 🔗 **Secure Links**: Generate unguessable links for watermarked documents
- 🗄️ **Database Backend**: MariaDB for reliable data persistence
- 🐳 **Docker Support**: Easy deployment with Docker Compose
- 📊 **Comprehensive Testing**: Unit tests, integration tests, and fuzzing tests

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Client                              │
│  (PGP-encrypted RMAP authentication + PDF download)         │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                     Flask Server                            │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────────┐   │
│  │ RMAP         │  │ Watermarking│  │ User Management  │   │
│  │ Endpoints    │─▶│ Engine      │  │ & Documents      │   │
│  └──────────────┘  └─────────────┘  └──────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    MariaDB Database                         │
│  (Users, Documents, Watermarked Versions)                   │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- **Python**: 3.11 or higher
- **Docker**: Latest version (for containerized deployment)
- **Docker Compose**: Latest version
- **Git**: For cloning the repository
- **Linux/macOS**: Recommended (Windows users should use WSL)

## Installation

### Development Setup

#### 1. Create Python Virtual Environment

```bash
cd server

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate
```

#### 2. Install Dependencies

```bash
# Install runtime dependencies
pip install -e .

# Install development dependencies (includes testing tools)
pip install -e ".[dev]"
```

#### 3. Set Up Database (Optional for Development)

For local development with a real database:

```bash
# Start MariaDB using Docker
cd ..
docker compose up db -d

# Wait for database to be ready
docker compose logs -f db
# Wait for "ready for connections" message
```

### Production Deployment

See the [Deployment](#deployment) section for detailed production deployment instructions.

## Configuration

### Environment Variables

Create a `.env` file in the project root by copying the sample:

```bash
cp sample.env .env
```

Edit `.env` with your configuration:

```bash
# Database Configuration
MARIADB_ROOT_PASSWORD=your_secure_root_password
MARIADB_USER=tatou
MARIADB_PASSWORD=your_secure_password

# Application Security
SECRET_KEY=your-secret-key-change-me
WATERMARK_KEY=your-strong-watermark-encryption-key
RMAP_ADMIN_KEY=your-strong-admin-key-for-leak-detection

# RMAP Configuration
PRIVATE_KEY_PASSPHRASE=your_private_key_passphrase

# Flag for CTF (if applicable)
FLAG_2=your_flag_value

# Optional: Logging
LOG_LEVEL=INFO
LOG_DIR=./logs
```

### Key Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `SECRET_KEY` | Flask secret key for session encryption | `dev-secret-change-me` |
| `STORAGE_DIR` | Directory for storing uploaded files | `./storage` |
| `TOKEN_TTL_SECONDS` | JWT token time-to-live | `86400` (24 hours) |
| `DB_HOST` | Database host | `db` |
| `DB_PORT` | Database port | `3306` |
| `DB_NAME` | Database name | `tatou` |
| `WATERMARK_METHOD` | Default watermarking method | `multi-location-robust-advanced` |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |

## Running the Application

### Development Server

#### Docker Compose

```bash
# Start all services (server, database, phpMyAdmin)
docker compose up --build

# Or run in detached mode
docker compose up --build -d

# Monitor logs
docker compose logs -f
```

Access the application:
- **Web Interface**: http://localhost:5000
- **API**: http://localhost:5000/api/
- **phpMyAdmin**: http://localhost:8080
- **Health Check**: http://localhost:5000/healthz

### Verify Installation

```bash
# Test health endpoint
curl http://localhost:5000/healthz

# Or with httpie
http :5000/healthz

# Expected response:
# {"message": "Server is running"}
```

## Testing

Tatou includes comprehensive testing suites covering unit tests, integration tests, API tests, and fuzzing tests.

### Run All Tests

```bash
cd server

# Activate virtual environment
source .venv/bin/activate

# Run all tests (unit + integration)
python -m pytest

# Run with markers
python -m pytest -m unit       # Only unit tests
python -m pytest -m integration # Only integration tests
python -m pytest -m slow       # Only slow tests
```

### Unit Tests

Unit tests test individual components in isolation.

```bash
cd server

# Activate virtual environment
source .venv/bin/activate

# Run all unit tests
python -m pytest test/unit/


**Unit Test Coverage**:
- Watermarking methods (add-after-eof, metadata, multi-location, PawStamp, bash-bridge)
- Security monitoring and validation
- Watermarking CLI utilities
- PDF processing utilities

### Integration Tests

Integration tests verify the complete API workflows.

```bash
cd server

# Run all integration tests
python -m pytest test/integration/


# Run with verbose output
python -m pytest test/integration/ -v
```

**Integration Test Coverage**:
- User authentication flow (signup, login, token management)
- Document management (upload, list, get, delete)
- Watermarking operations (create, read, list versions)
- RMAP protocol flow

### Coverage Analysis

Generate comprehensive test coverage reports:

```bash
cd server

# Run tests with coverage
python -m pytest --cov=src --cov-report=html --cov-report=term --cov-report=xml

# View coverage in terminal
python -m pytest --cov=src --cov-report=term-missing

# Generate HTML coverage report (recommended)
python -m pytest --cov=src --cov-report=html
# Open htmlcov/index.html in your browser
```

**Coverage Reports**:
- **Terminal**: Shows coverage percentage with missing lines
- **HTML**: Interactive report in `htmlcov/index.html`
- **XML**: Machine-readable report in `coverage.xml`

**Coverage Targets**:
- Current coverage target: 80%+ for core modules
- Critical security functions: 90%+ coverage

## Platform Specifications

For detailed platform requirements, see [Platform_specifications.md](Platform_specifications.md).

Key requirements:
- Users must be able to upload documents
- Documents without watermarks must be accessible only to owner
- Users must be able to generate watermarked versions
- Watermarks must be hard to remove
- Watermarks must allow secret retrieval
- Secure links must be unguessable
- Original document metadata must be confidential

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

## Acknowledgments

- Flask framework for web application
- PyMuPDF for PDF processing
- RMAP protocol for encrypted authentication
- Contributors and maintainers

## References

- [Flask Documentation](https://flask.palletsprojects.com/)
- [PyMuPDF Documentation](https://pymupdf.readthedocs.io/)
- [Docker Documentation](https://docs.docker.com/)
- [pytest Documentation](https://docs.pytest.org/)