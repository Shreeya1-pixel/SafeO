# SafeO — Real-time ERP Security Layer

**Multi-agent cybersecurity for enterprise apps.** Scores every input **0–100** → **ALLOW / WARN / BLOCK** before data hits the database. Four investigation agents collaborate through [Band](https://band.ai).

**Hackathon:** Band of Agents · Track 3 — Regulated & High-Stakes Workflows

---

## What you need

| Tool | Version | Used for |
|------|---------|----------|
| Python | 3.11+ | FastAPI backend |
| Node.js | 18+ | Standalone website |
| PostgreSQL | 14+ | Odoo database |
| Odoo | 19 | **Main demo UI** (dashboard) |

Optional: AMD GPU + vLLM for Tier-3 local LLM (no OpenAI required).

---

## Run everything (3 terminals)

Start in order: **backend → Odoo → website**.

### Terminal 1 — Backend (port 8001) **required**

```bash
cd backend
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example .env            # optional: Band keys — or use backend/.env.example
export PYTHONPATH="$(pwd)"
uvicorn safeo_backend.main:app --host 127.0.0.1 --port 8001 --reload
```

**Or** from repo root:

```bash
chmod +x scripts/run_all.sh && ./scripts/run_all.sh
```

| Check | URL |
|--------|-----|
| Swagger | http://127.0.0.1:8001/docs |
| Health | http://127.0.0.1:8001/health |
| API health | http://127.0.0.1:8001/v1/health + `Authorization: Bearer internal` |

---

### Terminal 2 — Odoo (port 8069) **main demo**

Odoo is not bundled. Use Odoo 19 + PostgreSQL on your machine.

**1. Configure `odoo.conf`**

Copy [`odoo.conf.example`](odoo.conf.example) to your Odoo install directory. Edit:

```ini
addons_path = addons,odoo/addons,/path/to/this-repo/odoo_module
db_name = securec_db
```

**2. Start Odoo**

```bash
cd /path/to/your/odoo
./venv/bin/python odoo-bin -c odoo.conf --http-port=8069
```

**3. Install SafeO module**

1. http://127.0.0.1:8069 → log in (`admin` / `admin` if you set that up)  
2. **Apps** → install **SafeO — ERP Risk Decision Engine** (`securec_odoo`)  
3. **Settings → SafeO** → **API URL** = `http://127.0.0.1:8001`

**4. Open demo dashboard**

| URL | What |
|-----|------|
| http://127.0.0.1:8069/odoo/safeo | SafeO dashboard (direct) |
| **SafeO ERP → Business Risk Dashboard** | Full UI: Live Feed, Sandbox, Investigations, Jira |

> Browser shows **“You are offline”**? Odoo is not running on 8069 — start Terminal 2. Not a Wi‑Fi issue.

**Jira (optional):** Settings → Jira URL, email, API token, project key. **BLOCK** events (risk ≥ 70%) can auto-create tickets.

---

### Terminal 3 — Standalone website (port 5174)

```bash
cd safeo_website
npm install
npm run dev
```

Open http://localhost:5174 — status cards for backend + Odoo, link to open SafeO in Odoo.

---

## Quick demo (hackathon)

1. Backend + Odoo running (website optional).  
2. Odoo → **Business Risk Dashboard** → **Sandbox**.  
3. Paste: `' OR 1=1; DROP TABLE users; --` → **Run Live Scan** → **BLOCK**.  
4. **Investigations** tab → 4 agents (Multilingual → Policy + Forensics → Remediation).  
5. **Risk → Action** → Jira ticket panel.

**API smoke test (no Odoo):**

```bash
curl -s -X POST http://127.0.0.1:8001/v1/scan \
  -H "Authorization: Bearer internal" \
  -H "Content-Type: application/json" \
  -d '{"input": "1 OR 1=1; DROP TABLE users;--", "context": {"user_id": "demo", "source_system": "test"}}' \
  | python3 -m json.tool
```

---

## Band integration

1. Create 4 agents at https://band.ai (Multilingual, Policy, Forensics, Remediation).  
2. Copy `.env.example` → `backend/.env`, fill `BAND_*` keys, set `BAND_ENABLED=true`.  
3. Restart backend — check `/v1/health` for `band_agents_connected`.  

Without Band: `BAND_ENABLED=false` — full demo still works. Promo: **BANDHACK26**.

Details: [QUICKSTART.md](QUICKSTART.md)

---

## Architecture

```
[Any ERP]              [Website :5174]
     │                        │
     └──────────┬─────────────┘
                ▼
       FastAPI :8001 (Tier 1→2→3 ML)
                │ BLOCK
                ▼
     Investigation Room (4 agents)
          │              │
          ▼              ▼
      Band chat      Odoo + Jira
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Pitch script: [docs/ppt.txt](docs/ppt.txt)

---

## Repository layout

```
backend/           FastAPI decision engine
odoo_module/       Odoo add-on (securec_odoo) — main demo UI
safeo_website/     Standalone site (:5174)
safeo_sdk/python/  Client for /v1/scan
scripts/run_all.sh Start backend only
QUICKSTART.md      GPU, vLLM, Band, troubleshooting
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Odoo “You are offline” | Start Odoo on 8069 |
| Dashboard “Backend offline” | Start backend; check Settings API URL |
| `401` on `/v1/*` | `Authorization: Bearer internal` |
| Band agents = 0 | Check `backend/.env` + network to band.ai |

---

## License

[LICENSE](LICENSE)
