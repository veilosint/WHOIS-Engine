import logging

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# --- Configuration ---
RATE_LIMIT = "5/minute"
WHOIS_API_BASE = "https://who-dat.as93.net"


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="WHOIS API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*\.(lovable\.app|lovableproject\.com|lovable\.dev)|http://localhost:\d+",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class WhoisRequest(BaseModel):
    domain: str


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "whois-api"}


@app.post("/api/whois")
@limiter.limit(RATE_LIMIT)
async def whois_lookup(request: Request, body: WhoisRequest):
    domain = body.domain.strip().lower()
    if not domain or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Strip protocol/path/port if user pasted a full URL
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    domain = domain.split(":", 1)[0]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{WHOIS_API_BASE}/{domain}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="WHOIS lookup timed out")
    except Exception as e:
        logging.exception(f"WHOIS request failed: {e}")
        raise HTTPException(status_code=500, detail=f"WHOIS error: {e}")

    if resp.status_code == 429:
        raise HTTPException(status_code=429, detail="WHOIS rate limit exceeded. Try again later.")
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=resp.status_code,
            detail=f"WHOIS upstream error: {resp.text[:200]}",
        )

    raw = resp.json()

    result = {
        "domain": raw.get("domain", domain),
        "isRegistered": raw.get("isRegistered", False),
        "registrar": None,
        "createdDate": None,
        "updatedDate": None,
        "expiryDate": None,
        "nameServers": [],
        "status": [],
        "registrant": {},
        "rawSource": raw.get("source"),
    }

    # Registrar / registrant info
    if isinstance(raw.get("entities"), list):
        for ent in raw["entities"]:
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [None, []])
            fields = {}
            if len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4:
                        fields[item[0]] = item[3]
            if "registrar" in roles:
                result["registrar"] = fields.get("fn") or fields.get("org")
            if "registrant" in roles:
                result["registrant"] = {
                    "name": fields.get("fn"),
                    "org": fields.get("org"),
                    "country": fields.get("adr"),
                }

    # Important dates
    if isinstance(raw.get("events"), list):
        for ev in raw["events"]:
            action = ev.get("eventAction", "")
            date = ev.get("eventDate")
            if action == "registration":
                result["createdDate"] = date
            elif action == "last changed":
                result["updatedDate"] = date
            elif action == "expiration":
                result["expiryDate"] = date

    # Nameservers
    if isinstance(raw.get("nameservers"), list):
        for ns in raw["nameservers"]:
            if isinstance(ns, dict) and ns.get("ldhName"):
                result["nameServers"].append(ns["ldhName"].lower())

    # Status flags
    if isinstance(raw.get("status"), list):
        result["status"] = raw["status"]

    return result
