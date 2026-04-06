# SafeO — Real-time ERP Security Layer

**One line:** Native Odoo integration + FastAPI risk engine that scores CRM, finance, HR, and web payloads before they commit — **ALLOW / WARN / BLOCK**.

**Hackathon track:** Business, Finance & Workforce ERP.

---

## Why judges care (30 seconds)

- **Real ERP surface:** Odoo menus, OWL dashboard, `crm.lead` hook, audit models — not a slide-only demo.
- **Real scoring stack:** Multi-signal risk engine (patterns, entropy, structural features, optional LLM tier) with clear API contracts.
- **3-minute run:** Backend → Odoo → open dashboard → one `curl` proves the engine.

---

## Architecture

```
  Odoo 19 (8069)                    FastAPI (8001)
 ┌──────────────────┐              ┌─────────────────────┐
 │ OWL Dashboard    │   HTTP       │ routes/erp, waf     │
 │ /safeo/* RPC     │ ──────────►  │ core/ml risk engine  │
 │ crm.lead → API   │              │ agents (behavior…)   │
 └──────────────────┘              └─────────────────────┘
```

Full diagram: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Features

- ERP gates: **transaction**, **employee activity**, **CRM lead**, **finance action**
- **Dashboard** feed: metrics, logs, per-module drill-down (OWL)
- **Decision lab** + **simulation** endpoints for scripted demos
- **Audit / decision** models stored in Odoo for reviewer queries
- Optional **LLM augmentation** (OpenRouter) — off by default

---

## Repository layout

```
SafeO/
├── README.md                 ← You are here
├── backend/                  # FastAPI application
│   ├── requirements.txt
│   ├── .env.example          # No secrets — copy to .env locally
│   └── safeo_backend/        # Python package
│       ├── main.py           # ASGI entry: app
│       ├── routes/           # HTTP routers (erp, waf, metrics, …)
│       ├── core/ml/          # Risk engine (scorer, entropy, keywords, …)
│       ├── agents/           # Input / output / behavior agents
│       ├── models/           # Pydantic schemas
│       └── utils/            # Shared helpers (extend as needed)
├── frontend/                 # README only — UI lives in Odoo module (OWL)
├── odoo_module/              # Addons path root for Odoo
│   ├── README.md
│   └── securec_odoo/         # Technical module name (do not rename casually)
├── docs/                     # Architecture notes
├── scripts/
│   └── run_all.sh            # Starts FastAPI on :8001
└── LICENSE
```

---

## Setup

### 1) Backend (required)

```bash
cd SafeO/backend
python3.11 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # optional: enable LLM keys
export PYTHONPATH="$(pwd)"
uvicorn safeo_backend.main:app --host 127.0.0.1 --port 8001 --reload
```

Or: `chmod +x scripts/run_all.sh && ./scripts/run_all.sh` from `SafeO/`.

- **Swagger:** http://127.0.0.1:8001/docs  
- **Health:** http://127.0.0.1:8001/health  

### 2) Frontend (Odoo OWL)

There is no separate `npm` app. See [frontend/README.md](frontend/README.md).

### 3) Odoo module

1. PostgreSQL + Odoo 19.
2. Add **`/path/to/repo/SafeO/odoo_module`** to `addons_path` in your Odoo config (local `odoo.conf` is often git-ignored — edit the file you actually start Odoo with).
3. Install module **SafeO — ERP Risk Decision Engine** (`securec_odoo`).
4. Set **API URL** to `http://127.0.0.1:8001` (Settings).

Details: [odoo_module/README.md](odoo_module/README.md).

---

## Demo script (under 3 minutes)

1. Terminal A: `./SafeO/scripts/run_all.sh` (or `uvicorn` as above).
2. Terminal B: start Odoo with `SafeO/odoo_module` on addons path.
3. Browser: http://127.0.0.1:8069 → login → **SafeO** → **Business Risk Dashboard**.
4. Terminal C — prove the engine:

```bash
curl -s -X POST http://127.0.0.1:8001/erp/crm/lead \
  -H "Content-Type: application/json" \
  -d '{"name":"Demo","message":"offshore wire to avoid audit","source":"web","user_id":"judge"}' | python3 -m json.tool
```

Expect a high risk score and **BLOCK** or **WARN** with structured JSON.

5. Open http://127.0.0.1:8001/erp/dashboard/summary for live demo payload.

---

## Sample API calls

```bash
# Health
curl -s http://127.0.0.1:8001/health

# ERP dashboard JSON (for UI / demos)
curl -s http://127.0.0.1:8001/erp/dashboard/summary | python3 -m json.tool

# Legacy WAF-style input (still supported)
curl -s -X POST http://127.0.0.1:8001/waf/input \
  -H "Content-Type: application/json" \
  -d '{"input_text":"'\'' OR 1=1--","module":"CRM","user_id":"demo"}' | python3 -m json.tool
```

---

## Screenshots

Add PNGs under `docs/screenshots/` if required for submission (optional).

---

## License

See [LICENSE](LICENSE).
