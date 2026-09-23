# MailTrail — Threat Intelligence & Forensics Platform

MailTrail is an advanced, full-stack email security platform that analyzes inbound emails for phishing, malicious intent, and impossible travel scenarios. It uses a modern React frontend and a FastAPI backend powered by MongoDB for persistence.

## 🚀 Key Features

*   **Heuristic NLP Engine**: Uses a rule-based Natural Language Processing engine and transformer models to detect urgency, lures, and malicious intent within email content.
*   **Geo-Intelligence & Impossible Travel**: Identifies the true physical location of sender IPs using MaxMind's DB-IP database. Automatically flags anomalous "impossible travel" logins by calculating the speed and distance between consecutive emails.
*   **Cryptographic Verification**: Analyzes SPF and DMARC authentication headers to ensure sender legitimacy.
*   **Forensic PDF Generation**: Automatically compiles tamper-evident PDF SOC reports for any flagged email, complete with SHA-256 evidence hashing.
*   **Modern React UI**: A seamless, single-page application (SPA) built with React.js, featuring live websockets, and interactive data visualizations.

## 🛠️ Technology Stack

*   **Frontend**: React.js, HTML5, CSS3 (CDN/Babel compilation for zero-build deployments).
*   **Backend**: Python 3, FastAPI, Uvicorn.
*   **Database**: MongoDB (Motor Async).
*   **Libraries**: `geoip2` (IP resolution), `fpdf2` (PDF generation), `pydantic` (Schema validation).

## ⚙️ Quickstart Guide

### Running with Docker (Recommended)

1. **Clone the repository**
2. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and fill in any required settings:
   ```bash
   cp .env.example .env
   ```
3. **Download GeoIP Database**:
   Download the `GeoLite2-City.mmdb` database and place it in the root of the project.
4. **Start the Application**:
   ```bash
   docker compose up -d --build
   ```
5. **Access the application**:
   - Web App: `http://localhost:8000`
   - API Docs: `http://localhost:8000/docs`

### Default Credentials
- **Admin**: `admin` / `admin123`
- **Analyst**: `analyst` / `analyst123`

## 📁 Project Structure

*   `/frontend/`: Contains the React SPA, core logic, and styling.
*   `/api/`: FastAPI route definitions and auth handlers.
*   `/services/`: Microservices for GeoIP, NLP, Heuristics, and Forensics.
*   `/models/`: Pydantic data schemas.
*   `/tests/`: Pytest automated test suite.
*   `/reports/`: Output directory for generated PDF forensic reports.