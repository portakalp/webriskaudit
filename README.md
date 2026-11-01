# Digital Risk Audit Platform

A comprehensive security audit platform for domains, featuring passive security scanning capabilities.

## 🏗️ Architecture

- **Frontend**: Next.js 16 + TypeScript + Tailwind CSS
- **Backend**: FastAPI + Python
- **Deployment**: Cloudflare Pages (Frontend) + Render.com (Backend)

## 🚀 Deployed URLs

- **Backend API**: https://digital-risk-audit-api.onrender.com
- **Frontend**: (Deploy to Cloudflare Pages)

## 📁 Project Structure

```
digital-risk-audit/
├── Backend/
│   ├── main.py              # FastAPI server
│   ├── SecurityAuditor.py   # Security audit logic
│   ├── requirements.txt     # Python dependencies
│   ├── runtime.txt          # Python version
│   └── .env.example         # Environment template
├── frontend/
│   ├── app/                 # Next.js app directory
│   ├── components/          # React components
│   ├── package.json         # Node dependencies
│   └── .env.local           # Local environment (not in git)
└── README.md
```

## 🔧 Local Development

### Backend Setup

```bash
cd Backend
pip install -r requirements.txt

# Create .env file from template
cp .env.example .env
# Add your HIBP_API_KEY to .env

# Run server
python main.py
# Server runs on http://localhost:8000
```

### Frontend Setup

```bash
cd frontend
npm install

# Update .env.local with backend URL
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local

# Run dev server
npm run dev
# Frontend runs on http://localhost:3000
```

## 🌐 Deployment

### Backend (Render.com)

Already deployed at: https://digital-risk-audit-api.onrender.com

**Settings used:**
- Root Directory: `Backend`
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Environment Variables:
  - `HIBP_API_KEY`: Your HaveIBeenPwned API key

### Frontend (Cloudflare Pages)

**Deploy Settings:**
- Project name: `digital-risk-audit`
- Production branch: `main`
- Framework preset: `Next.js`
- Build command: `cd frontend && npm install && npm run build`
- Build output directory: `frontend/.next`
- Root directory: `frontend`

**Environment Variables:**
- `NEXT_PUBLIC_API_URL`: `https://digital-risk-audit-api.onrender.com`

## 🔒 Security Features

- ✅ CORS enabled for cross-origin requests
- ✅ API keys stored in environment variables
- ✅ Secure environment configuration
- ✅ WAF detection
- ✅ SPF/DMARC email security checks
- ✅ SSL/TLS certificate validation
- ✅ IP reputation blacklist checking
- ✅ Security headers audit
- ✅ Information disclosure detection

## 📝 API Endpoints

### GET /
Root endpoint with API information

### GET /health
Health check endpoint

### POST /audit
Perform security audit on a domain

**Request Body:**
```json
{
  "domain": "example.com",
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "domain": "example.com",
  "report": {
    "waf": {...},
    "spf": {...},
    "dmarc": {...},
    "security_score": {...}
  }
}
```

## 🛠️ Technologies

- **Backend**: FastAPI, Uvicorn, Pydantic, DNSPython, Requests
- **Frontend**: Next.js 16, React 19, TypeScript, Tailwind CSS, Shadcn/UI
- **Security**: HaveIBeenPwned API, DNS blacklist checking, SSL validation

## 📄 License

Private Project

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
