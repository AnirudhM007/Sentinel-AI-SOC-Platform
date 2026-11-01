# Contributing to SENTINEL AI

Thank you for your interest in contributing to **SENTINEL AI**! We welcome improvements to agent behaviors, SIEM detection rules, ML anomaly models, and frontend features.

---

## Code of Conduct
This project is dedicated to providing a harassment-free and productive experience for everyone. Please be respectful and collaborative.

---

## Development Setup

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ (Node 20 recommended) and npm
- Git

### 2. Fork & Clone
```bash
git clone https://github.com/<your-username>/sentinel-ai.git
cd sentinel-ai
```

### 3. Backend Setup
```bash
cd backend
python -m venv venv

# Linux/macOS
source venv/bin/activate
# Windows PowerShell
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
python -m pytest tests -v
python run_backend.py
```
Backend will be live on `http://127.0.0.1:8008`.

### 4. Frontend Setup
```bash
cd ../frontend
npm install
npm run build
npm run dev
```
Frontend will be live on `http://localhost:5173`.

---

## Guidelines for Contributions

### Detection Rules (`backend/app/detection/rules.py`)
- Every new rule must inherit from `DetectionRule`.
- Rules must specify `rule_id`, `name`, `default_severity`, and `description`.
- Return structured alert dictionaries with `confidence`, `triggering_event_ids`, and `relevant_fields`.
- Add a corresponding test case in `backend/tests/test_detection.py`.

### LangGraph Agents (`backend/app/agents/`)
- Agent nodes must consume and return updates to `AgentState`.
- Do not make uncontrolled external API calls; use the modular `llm_provider` or `threat_intel_service`.
- Any referenced entities must be grounded in underlying SQLite telemetry.

### Frontend UI (`frontend/src/`)
- Strictly preserve the **Retro Neubrutalism** styling philosophy:
  - Solid 2px or 4px black borders (`border-2 border-black`).
  - Hard unblurred drop shadows (`shadow-[4px_4px_0px_0px_#000000]`).
  - Monospace font for telemetry, metrics, and technical labels (`font-mono`).
  - High-contrast cyber palette: Neon Lime (`#bef264`), Cyan (`#67e8f9`), Amber (`#fde047`), Coral/Red (`#ef4444`), Purple (`#c084fc`).
  - Tactile button press effects (`active:translate-x-[2px] active:translate-y-[2px]`).

---

## Running the Automated Test Suite

Before opening a pull request, verify that both the backend tests and frontend production builds pass without errors:

```bash
# 1. Backend tests
cd backend
python -m pytest tests -v

# 2. Frontend build
cd ../frontend
npm run build
```

---

## Submitting a Pull Request
1. Create a feature branch: `git checkout -b feat/your-feature-name`
2. Commit changes with clear messages: `git commit -m "feat(detection): add kerberoasting event rule"`
3. Push to your fork: `git push origin feat/your-feature-name`
4. Open a Pull Request against `main`.
