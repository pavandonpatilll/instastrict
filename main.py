import os
import re
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qs

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi.responses import RedirectResponse
try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

app = FastAPI(title="InstaRaksha API", version="2.0")
DB_NAME = os.getenv("DB_NAME", "instaraksha.db")
ADMIN_KEY = os.getenv("ADMIN_KEY", "change-this-admin-key")

# Development-friendly. Restrict allow_origins to your real domain before deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Admin-Key"],
)

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                profile_url TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        # Safe migration: preserve existing checks table and its saved records.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(checks)").fetchall()}
        if "answers" not in columns:
            conn.execute("ALTER TABLE checks ADD COLUMN answers TEXT NOT NULL DEFAULT '{}'")
        if "score" not in columns:
            conn.execute("ALTER TABLE checks ADD COLUMN score INTEGER NOT NULL DEFAULT 0")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS instagram_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instagram_user_id TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                account_type TEXT,
                encrypted_token TEXT NOT NULL,
                token_expires_at INTEGER,
                connected_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS instagram_oauth_states (
                state TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                rating INTEGER NOT NULL,
                message TEXT NOT NULL,
                approved INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()

init_db()


# ---------------- Official Instagram Login (Meta OAuth) ----------------
# Requires Instagram API with Instagram Login configured in Meta Developers.
INSTAGRAM_CLIENT_ID = os.getenv("INSTAGRAM_CLIENT_ID", "").strip()
INSTAGRAM_CLIENT_SECRET = os.getenv("INSTAGRAM_CLIENT_SECRET", "").strip()
INSTAGRAM_REDIRECT_URI = os.getenv(
    "INSTAGRAM_REDIRECT_URI",
    "https://instastrict.onrender.com/api/instagram/callback"
).strip()
INSTAGRAM_FRONTEND_URL = os.getenv(
    "INSTAGRAM_FRONTEND_URL",
    "https://instastrict-frontened.onrender.com/"
).strip()
INSTAGRAM_TOKEN_ENCRYPTION_KEY = os.getenv("INSTAGRAM_TOKEN_ENCRYPTION_KEY", "").strip()
INSTAGRAM_SCOPES = os.getenv("INSTAGRAM_SCOPES", "instagram_business_basic").strip()

def instagram_cipher():
    if Fernet is None:
        raise HTTPException(status_code=503, detail="Install cryptography in requirements.txt before enabling Instagram Connect.")
    if not INSTAGRAM_TOKEN_ENCRYPTION_KEY:
        raise HTTPException(status_code=503, detail="Instagram token encryption is not configured. Set INSTAGRAM_TOKEN_ENCRYPTION_KEY on Render.")
    try:
        return Fernet(INSTAGRAM_TOKEN_ENCRYPTION_KEY.encode("ascii"))
    except Exception:
        raise HTTPException(status_code=503, detail="INSTAGRAM_TOKEN_ENCRYPTION_KEY must be a valid Fernet key.")

def instagram_http(url, data=None):
    encoded = urlencode(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(
        url, data=encoded, method="POST" if data is not None else "GET",
        headers={"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {}
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", {}).get("message", "Instagram authorization failed.")
        except Exception:
            detail = "Instagram authorization failed."
        raise HTTPException(status_code=502, detail=detail)
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(status_code=502, detail="Could not connect to Instagram. Please try again.")

@app.get("/api/instagram/config")
def instagram_config():
    ready = bool(INSTAGRAM_CLIENT_ID and INSTAGRAM_CLIENT_SECRET and INSTAGRAM_TOKEN_ENCRYPTION_KEY)
    return {
        "enabled": ready,
        "message": "" if ready else "Instagram Connect is awaiting Meta OAuth credentials and token encryption setup."
    }

@app.get("/api/instagram/connect")
def instagram_connect():
    if not INSTAGRAM_CLIENT_ID or not INSTAGRAM_CLIENT_SECRET:
        raise HTTPException(status_code=503, detail="Instagram Login is not configured yet. Add Instagram Client ID and Secret on Render.")
    instagram_cipher()  # Validate encryption before sending user to consent.
    import secrets
    state = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute("DELETE FROM instagram_oauth_states WHERE created_at < ?", (int(time.time()) - 900,))
        conn.execute("INSERT INTO instagram_oauth_states(state, created_at) VALUES (?, ?)", (state, int(time.time())))
        conn.commit()
    params = {
        "client_id": INSTAGRAM_CLIENT_ID,
        "redirect_uri": INSTAGRAM_REDIRECT_URI,
        "response_type": "code",
        "scope": INSTAGRAM_SCOPES,
        "state": state
    }
    return {"auth_url": "https://www.instagram.com/oauth/authorize?" + urlencode(params)}

@app.get("/api/instagram/callback")
def instagram_callback(code: str = "", state: str = "", error: str = "", error_description: str = ""):
    if error:
        return RedirectResponse(INSTAGRAM_FRONTEND_URL + "?instagram=denied")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Instagram did not return an authorization code.")
    with get_db() as conn:
        row = conn.execute("SELECT created_at FROM instagram_oauth_states WHERE state=?", (state,)).fetchone()
        conn.execute("DELETE FROM instagram_oauth_states WHERE state=?", (state,))
        conn.commit()
    if not row or int(time.time()) - int(row["created_at"]) > 900:
        raise HTTPException(status_code=400, detail="Instagram authorization state expired. Please connect again.")

    short_token = instagram_http("https://api.instagram.com/oauth/access_token", {
        "client_id": INSTAGRAM_CLIENT_ID,
        "client_secret": INSTAGRAM_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "redirect_uri": INSTAGRAM_REDIRECT_URI,
        "code": code
    })
    access_token = short_token.get("access_token")
    ig_user_id = str(short_token.get("user_id") or "")
    if not access_token or not ig_user_id:
        raise HTTPException(status_code=502, detail="Instagram did not return a usable account token.")

    long_token = instagram_http(
        "https://graph.instagram.com/access_token?" + urlencode({
            "grant_type": "ig_exchange_token",
            "client_secret": INSTAGRAM_CLIENT_SECRET,
            "access_token": access_token
        })
    )
    access_token = long_token.get("access_token", access_token)
    expires_in = int(long_token.get("expires_in", 0) or 0)
    profile = instagram_http(
        "https://graph.instagram.com/v25.0/me?" + urlencode({
            "fields": "user_id,username,account_type",
            "access_token": access_token
        })
    )
    username = str(profile.get("username") or "")
    ig_user_id = str(profile.get("user_id") or ig_user_id)
    if not username:
        raise HTTPException(status_code=502, detail="Instagram connected but profile details could not be read.")
    encrypted = instagram_cipher().encrypt(access_token.encode("utf-8")).decode("ascii")
    now = datetime.now(timezone.utc).isoformat()
    expires_at = int(time.time()) + expires_in if expires_in else None
    with get_db() as conn:
        conn.execute("""
            INSERT INTO instagram_connections
            (instagram_user_id, username, account_type, encrypted_token, token_expires_at, connected_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(instagram_user_id) DO UPDATE SET
              username=excluded.username, account_type=excluded.account_type,
              encrypted_token=excluded.encrypted_token, token_expires_at=excluded.token_expires_at,
              updated_at=excluded.updated_at
        """, (ig_user_id, username, profile.get("account_type", ""), encrypted, expires_at, now, now))
        conn.commit()
    return RedirectResponse(INSTAGRAM_FRONTEND_URL + "?instagram=connected&username=" + username)


class ProfileRequest(BaseModel):
    profile_url: str = Field(min_length=10, max_length=300)
    answers: dict[str, bool] = Field(default_factory=dict)

class ReviewRequest(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    rating: int = Field(ge=1, le=5)
    message: str = Field(min_length=5, max_length=500)

def validate_instagram_url(value: str):
    value = value.strip()
    if not value.startswith(("https://", "http://")):
        value = "https://" + value
    parsed = urlparse(value)
    if (parsed.hostname or "").lower() not in ("instagram.com", "www.instagram.com"):
        raise HTTPException(status_code=400, detail="Please enter a valid Instagram profile URL.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 1 or not re.fullmatch(r"[A-Za-z0-9._]{1,30}", parts[0]):
        raise HTTPException(status_code=400, detail="Enter a profile URL, not a post, reel or story.")
    username = parts[0]
    return username, f"https://www.instagram.com/{username}/"

def require_admin(key: str):
    if not ADMIN_KEY or ADMIN_KEY == "change-this-admin-key":
        raise HTTPException(status_code=503, detail="Set a strong ADMIN_KEY environment variable before using admin endpoints.")
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key.")

@app.get("/")
def home():
    return {"message": "InstaRaksha API is running", "status": "ok"}

@app.get("/api/health")
def health():
    return {"status": "online", "service": "InstaRaksha"}

@app.post("/api/check")
def submit_profile(data: ProfileRequest):
    username, profile_url = validate_instagram_url(data.profile_url)
    allowed = {"two_factor", "unique_password", "email_phone", "login_activity", "third_party_apps"}
    answers = {key: bool(data.answers.get(key, False)) for key in allowed}
    score = round(sum(answers.values()) / len(allowed) * 100)
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO checks (username, profile_url, created_at, answers, score)
               VALUES (?, ?, ?, ?, ?)""",
            (username, profile_url, now, json.dumps(answers), score)
        )
        conn.commit()
        record_id = cursor.lastrowid

    tips = [
        "Turn on two-factor authentication in Instagram.",
        "Use a unique password and never share it.",
        "Keep your recovery email and phone number current.",
        "Review login activity and log out unknown sessions.",
        "Remove apps or websites you no longer trust."
    ]
    return {
        "success": True,
        "id": record_id,
        "username": username,
        "profile_url": profile_url,
        "score": score,
        "score_label": "Security habits self-assessment",
        "notice": "This percentage is calculated only from your answers. We did not access or scan your Instagram account. It cannot predict or prevent suspension.",
        "answers": answers,
        "tips": tips
    }

@app.post("/api/reviews")
def create_review(data: ReviewRequest):
    name = data.name.strip()
    message = data.message.strip()
    if not name or not message:
        raise HTTPException(status_code=400, detail="Name and review are required.")
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO reviews (name, rating, message, approved, created_at) VALUES (?, ?, ?, 0, ?)",
            (name, data.rating, message, now)
        )
        conn.commit()
        review_id = cursor.lastrowid
    return {"success": True, "id": review_id, "message": "Thank you! Your review is pending admin approval."}

@app.get("/api/reviews")
def public_reviews():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, rating, message, created_at FROM reviews WHERE approved=1 ORDER BY id DESC LIMIT 30"
        ).fetchall()
    return {"reviews": [dict(row) for row in rows]}

@app.get("/api/admin/checks")
def admin_checks(x_admin_key: str = Header(default="")):
    # Kept for compatibility with the original admin page/API.
    require_admin(x_admin_key)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, profile_url, created_at, score, answers FROM checks ORDER BY id DESC"
        ).fetchall()
    return {"success": True, "total": len(rows), "users": [dict(row) for row in rows]}

@app.get("/api/admin/stats")
def admin_stats(x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        review_total = conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM reviews WHERE approved=0").fetchone()[0]
    return {"total_profiles": total, "total_reviews": review_total, "pending_reviews": pending, "status": "online"}

@app.get("/api/admin/dashboard")
def admin_dashboard(x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    with get_db() as conn:
        checks = conn.execute("SELECT id, username, profile_url, created_at, score, answers FROM checks ORDER BY id DESC LIMIT 200").fetchall()
        reviews = conn.execute("SELECT id, name, rating, message, approved, created_at FROM reviews ORDER BY id DESC LIMIT 200").fetchall()
        total_checks = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        total_reviews = conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM reviews WHERE approved=0").fetchone()[0]
    return {
        "total_checks": total_checks,
        "total_reviews": total_reviews,
        "pending_reviews": pending,
        "checks": [dict(row) for row in checks],
        "reviews": [dict(row) for row in reviews]
    }

@app.post("/api/admin/reviews/{review_id}/approve")
def approve_review(review_id: int, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    with get_db() as conn:
        cursor = conn.execute("UPDATE reviews SET approved=1 WHERE id=?", (review_id,))
        conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Review not found.")
    return {"success": True}

@app.post("/api/admin/reviews/{review_id}/reject")
def reject_review(review_id: int, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM reviews WHERE id=?", (review_id,))
        conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Review not found.")
    return {"success": True}

# ---------------- Razorpay subscriptions integration ----------------
import base64
import hashlib
import hmac
import time
import urllib.error
import urllib.request

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "").strip()
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()
RAZORPAY_PLAN_ID = os.getenv("RAZORPAY_PLAN_ID", "plan_Ty9odB5ggH2smm").strip()
TRIAL_AMOUNT_PAISE = 100
TRIAL_START_DELAY_SECONDS = 24 * 60 * 60

def payment_db_init():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS payment_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT UNIQUE NOT NULL,
                payment_id TEXT,
                plan_type TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                customer_name TEXT,
                customer_email TEXT,
                customer_contact TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subscription_id TEXT UNIQUE NOT NULL,
                plan_type TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                status TEXT NOT NULL,
                customer_name TEXT,
                customer_email TEXT,
                customer_contact TEXT,
                trial_order_id TEXT,
                first_charge_at INTEGER,
                latest_payment_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()

payment_db_init()

def razorpay_request(method: str, path: str, payload=None):
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=503, detail="Razorpay keys are not configured on the backend.")
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    token = base64.b64encode(f"{RAZORPAY_KEY_ID}:{RAZORPAY_KEY_SECRET}".encode()).decode()
    request = urllib.request.Request(
        "https://api.razorpay.com/v1" + path,
        data=body,
        method=method,
        headers={"Authorization": "Basic " + token, "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", {}).get("description", "Razorpay request failed.")
        except Exception:
            detail = "Razorpay request failed."
        raise HTTPException(status_code=502, detail=detail)
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(status_code=502, detail="Could not connect to Razorpay. Please try again.")

def verify_signature(message: str, signature: str, secret: str):
    expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")

def clean_customer(value, max_len):
    return str(value or "").strip()[:max_len]

class CheckoutCustomer(BaseModel):
    name: str = Field(default="", max_length=100)
    email: str = Field(default="", max_length=150)
    contact: str = Field(default="", max_length=20)

class TrialOrderRequest(CheckoutCustomer):
    pass

class TrialCompleteRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

class SubscriptionVerifyRequest(BaseModel):
    razorpay_payment_id: str
    razorpay_subscription_id: str
    razorpay_signature: str

def save_subscription(sub, plan_type, customer, trial_order_id=None, first_charge_at=None):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute("""
            INSERT INTO subscriptions
            (subscription_id, plan_type, plan_id, status, customer_name, customer_email,
             customer_contact, trial_order_id, first_charge_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subscription_id) DO UPDATE SET
              status=excluded.status, updated_at=excluded.updated_at
        """, (
            sub["id"], plan_type, RAZORPAY_PLAN_ID, sub.get("status", "created"),
            customer.get("name", ""), customer.get("email", ""), customer.get("contact", ""),
            trial_order_id, first_charge_at, now, now
        ))
        conn.commit()

@app.get("/api/payments/config")
def payments_config():
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        return {"enabled": False, "message": "Payments are being configured."}
    return {"enabled": True, "key_id": RAZORPAY_KEY_ID, "plan_id": RAZORPAY_PLAN_ID}

@app.post("/api/payments/trial/order")
def create_trial_order(data: TrialOrderRequest):
    if not RAZORPAY_PLAN_ID:
        raise HTTPException(status_code=503, detail="Razorpay monthly plan is not configured.")
    customer = {
        "name": clean_customer(data.name, 100),
        "email": clean_customer(data.email, 150),
        "contact": clean_customer(data.contact, 20)
    }
    order = razorpay_request("POST", "/orders", {
        "amount": TRIAL_AMOUNT_PAISE,
        "currency": "INR",
        "receipt": "ir_trial_" + str(int(time.time())),
        "notes": {"plan_type": "trial_1_then_159", "customer_name": customer["name"]}
    })
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute("""
            INSERT INTO payment_orders
            (order_id, plan_type, amount, status, customer_name, customer_email, customer_contact, created_at, updated_at)
            VALUES (?, 'trial_1_then_159', ?, 'created', ?, ?, ?, ?, ?)
        """, (order["id"], TRIAL_AMOUNT_PAISE, customer["name"], customer["email"], customer["contact"], now, now))
        conn.commit()
    return {"order_id": order["id"], "amount": order["amount"], "currency": order["currency"], "key_id": RAZORPAY_KEY_ID}

@app.post("/api/payments/trial/complete")
def complete_trial(data: TrialCompleteRequest):
    if not verify_signature(
        data.razorpay_order_id + "|" + data.razorpay_payment_id,
        data.razorpay_signature, RAZORPAY_KEY_SECRET
    ):
        raise HTTPException(status_code=400, detail="Invalid payment signature.")
    payment = razorpay_request("GET", "/payments/" + data.razorpay_payment_id)
    if payment.get("order_id") != data.razorpay_order_id or payment.get("amount") != TRIAL_AMOUNT_PAISE or payment.get("status") != "captured":
        raise HTTPException(status_code=400, detail="The ₹1 payment is not confirmed as captured.")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM payment_orders WHERE order_id=?", (data.razorpay_order_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Trial order not found.")
        conn.execute("UPDATE payment_orders SET payment_id=?, status='captured', updated_at=? WHERE order_id=?",
                     (data.razorpay_payment_id, datetime.now(timezone.utc).isoformat(), data.razorpay_order_id))
        existing = conn.execute("SELECT subscription_id FROM subscriptions WHERE trial_order_id=?", (data.razorpay_order_id,)).fetchone()
        conn.commit()
    if existing:
        sub = razorpay_request("GET", "/subscriptions/" + existing["subscription_id"])
        return {"subscription_id": sub["id"], "status": sub.get("status"), "start_at": sub.get("start_at")}
    customer = {"name": row["customer_name"], "email": row["customer_email"], "contact": row["customer_contact"]}
    first_charge_at = int(time.time()) + TRIAL_START_DELAY_SECONDS
    sub = razorpay_request("POST", "/subscriptions", {
        "plan_id": RAZORPAY_PLAN_ID,
        "total_count": 1200,
        "quantity": 1,
        "customer_notify": False,
        "start_at": first_charge_at,
        # Authorization must be completed before the scheduled first billing time.
        # Razorpay's UPI subscription schedule is fixed at creation; UPI subscriptions
        # cannot be edited later to move the start time after authorization.
        "expire_by": first_charge_at - 60,
        "notes": {
            "plan_type": "trial_1_then_159",
            "trial_order_id": data.razorpay_order_id,
            "customer_name": customer["name"]
        }
    })
    save_subscription(sub, "trial_1_then_159", customer, data.razorpay_order_id, first_charge_at)
    return {"subscription_id": sub["id"], "status": sub.get("status"), "start_at": first_charge_at}

@app.post("/api/payments/monthly/create")
def create_monthly_subscription(data: CheckoutCustomer):
    customer = {
        "name": clean_customer(data.name, 100),
        "email": clean_customer(data.email, 150),
        "contact": clean_customer(data.contact, 20)
    }
    sub = razorpay_request("POST", "/subscriptions", {
        "plan_id": RAZORPAY_PLAN_ID,
        "total_count": 1200,
        "quantity": 1,
        "customer_notify": False,
        "notes": {"plan_type": "direct_159_monthly", "customer_name": customer["name"]}
    })
    save_subscription(sub, "direct_159_monthly", customer)
    return {"subscription_id": sub["id"], "status": sub.get("status"), "key_id": RAZORPAY_KEY_ID}

@app.post("/api/payments/subscription/verify")
def verify_subscription(data: SubscriptionVerifyRequest):
    if not verify_signature(
        data.razorpay_payment_id + "|" + data.razorpay_subscription_id,
        data.razorpay_signature, RAZORPAY_KEY_SECRET
    ):
        raise HTTPException(status_code=400, detail="Invalid subscription signature.")
    sub = razorpay_request("GET", "/subscriptions/" + data.razorpay_subscription_id)
    payment = razorpay_request("GET", "/payments/" + data.razorpay_payment_id)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute("""
            UPDATE subscriptions SET status=?, latest_payment_id=?, updated_at=? WHERE subscription_id=?
        """, (sub.get("status", "created"), data.razorpay_payment_id, now, data.razorpay_subscription_id))
        conn.execute("""
            INSERT OR IGNORE INTO payment_orders
            (order_id, payment_id, plan_type, amount, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("subauth_" + data.razorpay_subscription_id, data.razorpay_payment_id,
              "trial_1_then_159" if any(x for x in [sub.get("notes", {}).get("trial_order_id")]) else "direct_159_monthly",
              payment.get("amount", 0), payment.get("status", "authorized"), now, now))
        conn.commit()
    return {"success": True, "subscription_status": sub.get("status"), "payment_status": payment.get("status")}

@app.post("/api/payments/webhook")
async def razorpay_webhook(request: Request):
    raw = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")
    if not RAZORPAY_WEBHOOK_SECRET or not verify_signature(raw.decode("utf-8"), signature, RAZORPAY_WEBHOOK_SECRET):
        raise HTTPException(status_code=400, detail="Invalid webhook signature.")
    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook payload.")
    payload = event.get("payload", {})
    sub_entity = payload.get("subscription", {}).get("entity", {})
    pay_entity = payload.get("payment", {}).get("entity", {})
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        if sub_entity.get("id"):
            conn.execute("UPDATE subscriptions SET status=?, updated_at=? WHERE subscription_id=?",
                         (sub_entity.get("status", "unknown"), now, sub_entity["id"]))
        if pay_entity.get("id"):
            sub_id = pay_entity.get("subscription_id", "")
            conn.execute("""
                INSERT INTO payment_orders
                (order_id, payment_id, plan_type, amount, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(order_id) DO UPDATE SET payment_id=excluded.payment_id,
                status=excluded.status, updated_at=excluded.updated_at
            """, ("webhook_" + pay_entity["id"], pay_entity["id"],
                  "subscription_payment" if sub_id else "one_time",
                  pay_entity.get("amount", 0), pay_entity.get("status", "unknown"), now, now))
            if sub_id:
                conn.execute("UPDATE subscriptions SET latest_payment_id=?, updated_at=? WHERE subscription_id=?",
                             (pay_entity["id"], now, sub_id))
        conn.commit()
    return {"received": True}

@app.get("/api/admin/payments")
def admin_payments(x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    with get_db() as conn:
        orders = conn.execute("SELECT * FROM payment_orders ORDER BY id DESC LIMIT 500").fetchall()
        subs = conn.execute("SELECT * FROM subscriptions ORDER BY id DESC LIMIT 500").fetchall()
        instagram_accounts = conn.execute(
            "SELECT id, instagram_user_id, username, account_type, token_expires_at, connected_at, updated_at FROM instagram_connections ORDER BY id DESC LIMIT 500"
        ).fetchall()
    return {
        "success": True,
        "payments": [dict(row) for row in orders],
        "subscriptions": [dict(row) for row in subs],
        "instagram_accounts": [dict(row) for row in instagram_accounts]
    }
