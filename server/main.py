import os, time, ipaddress
from typing import List, Optional, Dict
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
import aiosmtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# Load .env before reading any environment variables
# 1) Load from current working directory (if present)
load_dotenv()
# 2) Also try loading a .env that lives alongside this file (server/ directory)
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    _local_env = os.path.join(_here, ".env")
    if os.path.exists(_local_env):
        load_dotenv(_local_env, override=True)
except Exception:
    pass

# Environment configuration
SECURITY_MAILBOX = os.getenv("SECURITY_MAILBOX", "sec-joby@joby.aero")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_SENDER = os.getenv("SMTP_SENDER")  # optional override for From header
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "false").lower() in ("1", "true", "yes")  # implicit TLS (SMTPS, e.g., port 465)
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() in ("1", "true", "yes")  # upgrade to TLS after connect (e.g., port 587)
DEDUP_WINDOW_SECONDS = int(os.getenv("DEDUP_WINDOW_SECONDS", "3600"))

# Optional IP allowlist; e.g. "10.0.0.0/8,192.168.0.0/16"
ALLOWLIST_CIDRS = [c.strip() for c in os.getenv("ALLOWLIST_CIDRS", "").split(",") if c.strip()]

# During dev you can set to "*"; ideally set to the extension origin like chrome-extension://<id>
EXTENSION_ORIGIN = os.getenv("EXTENSION_ORIGIN", "*")

app = FastAPI(title="Joby Phishing Report API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[EXTENSION_ORIGIN] if EXTENSION_ORIGIN != "*" else ["*"],
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def _log_config():
    # Basic config log to confirm which SMTP settings are active (no secrets)
    try:
        print(
            "[Phishing-API] SMTP config:",
            {
                "host": SMTP_HOST,
                "port": SMTP_PORT,
                "use_tls": SMTP_USE_TLS,
                "starttls": SMTP_STARTTLS,
                "sender": SMTP_SENDER or SMTP_USER or "no-reply@joby.aero",
                "user_set": bool(SMTP_USER),
            },
        )
    except Exception as _:
        pass


class AuthStatus(BaseModel):
    status: str = Field(..., pattern="^(pass|fail|none|unknown)$")


class AuthResults(BaseModel):
    dkim: AuthStatus = AuthStatus(status="unknown")
    spf: AuthStatus = AuthStatus(status="unknown")
    dmarc: AuthStatus = AuthStatus(status="unknown")


class ReportPayload(BaseModel):
    message_id: str
    subject: str
    from_address: EmailStr
    to_address: Optional[EmailStr] = None
    final_score: int = Field(..., ge=0, le=100)
    heuristic_score: int = Field(..., ge=0, le=120)
    llm_score: Optional[int] = Field(default=None, ge=0, le=100)
    details: List[str] = Field(default_factory=list)
    suspicious_elements: List[str] = Field(default_factory=list)
    auth_results: AuthResults = AuthResults()
    analysed_at: Optional[datetime] = None


RECENT_REPORTS: Dict[str, float] = {}


def is_recent_duplicate(message_id: str) -> bool:
    now = time.time()
    last = RECENT_REPORTS.get(message_id)
    if last and (now - last) < DEDUP_WINDOW_SECONDS:
        return True
    RECENT_REPORTS[message_id] = now
    return False


def check_ip_allowlist(client_ip: str):
    if not ALLOWLIST_CIDRS:
        return
    ip = ipaddress.ip_address(client_ip)
    for cidr in ALLOWLIST_CIDRS:
        if ip in ipaddress.ip_network(cidr, strict=False):
            return
    raise HTTPException(status_code=403, detail="Forbidden (IP not allowlisted)")


def build_email(payload: ReportPayload) -> EmailMessage:
    analysed_at = payload.analysed_at or datetime.now(timezone.utc)
    details_str = "\n".join(f"- {d}" for d in payload.details[:50]) or "(none)"
    suspicious_str = "\n".join(f"- {s}" for s in payload.suspicious_elements[:50]) or "(none)"

    body = f"""PHISHING REPORT (Auto-generated)

Email Subject: {payload.subject}
Sender: {payload.from_address}
Recipient: {payload.to_address or 'Unknown'}
Message ID: {payload.message_id}
Analysed At (UTC): {analysed_at.isoformat()}

Scores:
- Heuristic: {payload.heuristic_score}
- LLM: {payload.llm_score if payload.llm_score is not None else 'N/A'}
- Final: {payload.final_score}/100

Authentication:
- DKIM: {payload.auth_results.dkim.status}
- SPF: {payload.auth_results.spf.status}
- DMARC: {payload.auth_results.dmarc.status}

Details:
{details_str}

Suspicious Elements:
{suspicious_str}
"""
    msg = EmailMessage()
    sender = SMTP_SENDER or SMTP_USER or "no-reply@joby.aero"
    msg["From"] = sender
    msg["To"] = SECURITY_MAILBOX
    msg["Subject"] = "Phishing Report - Joby Security Extension"
    msg.set_content(body)
    return msg


async def send_email(msg: EmailMessage):
    # Choose TLS mode per configuration
    if SMTP_USE_TLS:
        client = aiosmtplib.SMTP(hostname=SMTP_HOST, port=SMTP_PORT, use_tls=True, timeout=20)
    else:
        client = aiosmtplib.SMTP(hostname=SMTP_HOST, port=SMTP_PORT, start_tls=SMTP_STARTTLS, timeout=20)

    async with client:
        if SMTP_USER and SMTP_PASS:
            await client.login(SMTP_USER, SMTP_PASS)
        # Explicitly set envelope sender and recipients
        envelope_sender = SMTP_SENDER or SMTP_USER or "no-reply@joby.aero"
        envelope_recipients = [SECURITY_MAILBOX]
        await client.send_message(msg, sender=envelope_sender, recipients=envelope_recipients)


@app.post("/report-phishing", status_code=202)
async def report_phishing(request: Request, payload: ReportPayload, background: BackgroundTasks):
    client_ip = request.client.host if request.client else "0.0.0.0"
    check_ip_allowlist(client_ip)

    if is_recent_duplicate(payload.message_id):
        return {"status": "duplicate_ignored", "message_id": payload.message_id}

    msg = build_email(payload)
    background.add_task(send_email, msg)
    return {"status": "accepted", "message_id": payload.message_id}
