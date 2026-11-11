import os
import re
import json
import sqlite3
import time
import urllib.error
import urllib.request
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


# ---------------- Instagram API with Meta Unified Login ----------------
# New Meta apps use Facebook Login for Business with a config_id.
# The configuration created in Meta controls the requested permissions/assets;
# do not send a legacy Instagram scope list in this flow.
INSTAGRAM_CLIENT_ID = os.getenv("INSTAGRAM_CLIENT_ID", "").strip()
INSTAGRAM_CLIENT_SECRET = os.getenv("INSTAGRAM_CLIENT_SECRET", "").strip()
INSTAGRAM_CONFIG_ID = os.getenv("INSTAGRAM_CONFIG_ID", "").strip()
INSTAGRAM_GRAPH_VERSION = os.getenv("INSTAGRAM_GRAPH_VERSION", "v25.0").strip()
INSTAGRAM_REDIRECT_URI = os.getenv(
    "INSTAGRAM_REDIRECT_URI",
    "https://instastrict.onrender.com/api/instagram/callback"
).strip()
INSTAGRAM_FRONTEND_URL = os.getenv(
    "INSTAGRAM_FRONTEND_URL",
    "https://instastrict-frontened.onrender.com/"
).strip()
INSTAGRAM_TOKEN_ENCRYPTION_KEY = os.getenv("INSTAGRAM_TOKEN_ENCRYPTION_KEY", "").strip()


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
            payload = json.loads(exc.read().decode("utf-8"))
            detail = payload.get("error", {}).get("message", "Meta authorization failed.")
        except Exception:
            detail = "Meta authorization failed."
        raise HTTPException(status_code=502, detail=detail)
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(status_code=502, detail="Could not connect to Meta. Please try again.")


def instagram_frontend_redirect(result, **extra):
    params = {"instagram": result}
    params.update({key: str(value) for key, value in extra.items() if value is not None})
    return RedirectResponse(INSTAGRAM_FRONTEND_URL.rstrip("/") + "/?" + urlencode(params))


def instagram_graph_url(path, **params):
    query = urlencode(params)
    return f"https://graph.facebook.com/{INSTAGRAM_GRAPH_VERSION}/{path}" + (f"?{query}" if query else "")


@app.get("/api/instagram/config")
def instagram_config():
    ready = bool(
        INSTAGRAM_CLIENT_ID and INSTAGRAM_CLIENT_SECRET
        and INSTAGRAM_CONFIG_ID and INSTAGRAM_TOKEN_ENCRYPTION_KEY
    )
    return {
        "enabled": ready,
        "message": "" if ready else "Instagram Unified Login is awaiting App ID, App Secret, Configuration ID and token encryption setup."
    }


@app.get("/api/instagram/connect")
def instagram_connect():
    if not INSTAGRAM_CLIENT_ID or not INSTAGRAM_CLIENT_SECRET or not INSTAGRAM_CONFIG_ID:
        raise HTTPException(
            status_code=503,
            detail="Instagram Unified Login is not configured. Add INSTAGRAM_CLIENT_ID, INSTAGRAM_CLIENT_SECRET and INSTAGRAM_CONFIG_ID on Render."
        )
    instagram_cipher()  # Validate encryption before sending the visitor to Meta consent.
    import secrets
    state = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute(
            "DELETE FROM instagram_oauth_states WHERE created_at < ?",
            (int(time.time()) - 900,)
        )
        conn.execute(
            "INSERT INTO instagram_oauth_states(state, created_at) VALUES (?, ?)",
            (state, int(time.time()))
        )
        conn.commit()

    # Match the URL generated by Meta's Unified Login configuration.
    params = {
        "client_id": INSTAGRAM_CLIENT_ID,
        "config_id": INSTAGRAM_CONFIG_ID,
        "display": "popup",
        "override_default_response_type": "true",
        "redirect_uri": INSTAGRAM_REDIRECT_URI,
        "response_type": "code",
        "state": state,
        "prompt": "login"
    }
    return {"auth_url": "https://www.facebook.com/dialog/oauth?" + urlencode(params)}


@app.get("/api/instagram/callback")
def instagram_callback(code: str = "", state: str = "", error: str = "", error_description: str = ""):
    if error:
        return instagram_frontend_redirect(
            "denied",
            message=(error_description or error or "Meta authorization was cancelled.")[:240]
        )
    if not code or not state:
        raise HTTPException(status_code=400, detail="Meta did not return an authorization code.")

    with get_db() as conn:
        row = conn.execute(
            "SELECT created_at FROM instagram_oauth_states WHERE state=?",
            (state,)
        ).fetchone()
        conn.execute("DELETE FROM instagram_oauth_states WHERE state=?", (state,))
        conn.commit()

    if not row or int(time.time()) - int(row["created_at"]) > 900:
        raise HTTPException(status_code=400, detail="Meta authorization state expired. Please connect again.")

    try:
        # Unified Login exchanges the code through the Facebook Graph OAuth endpoint.
        token_data = instagram_http(
            instagram_graph_url("oauth/access_token",
                client_id=INSTAGRAM_CLIENT_ID,
                client_secret=INSTAGRAM_CLIENT_SECRET,
                redirect_uri=INSTAGRAM_REDIRECT_URI,
                code=code
            )
        )
        access_token = str(token_data.get("access_token") or "")
        if not access_token:
            raise HTTPException(status_code=502, detail="Meta did not return an access token.")

        expires_in = int(token_data.get("expires_in", 0) or 0)

        # Unified Login returns a Business Integration System User token.
        # First identify the business attached to this token, then enumerate every
        # Instagram asset assigned to it. The edge can be paginated; reading only
        # the first response can otherwise miss the selected account.
        identity = instagram_http(instagram_graph_url(
            "me", fields="id,client_business_id", access_token=access_token
        ))
        client_business_id = str(identity.get("client_business_id") or "")

        accounts_by_id = {}
        after = ""
        seen_cursors = set()
        complete = False
        for _page in range(100):
            page_params = {
                "fields": "id,username",
                "limit": 100,
                "access_token": access_token,
            }
            if after:
                page_params["after"] = after
            assigned = instagram_http(instagram_graph_url(
                "me/assigned_instagram_accounts", **page_params
            ))
            page_accounts = assigned.get("data")
            if not isinstance(page_accounts, list):
                raise HTTPException(
                    status_code=502,
                    detail="Meta returned an unexpected Instagram asset response. Please reconnect and try again."
                )
            for item in page_accounts:
                account_id = str(item.get("id") or "")
                if account_id:
                    accounts_by_id[account_id] = item
            next_cursor = str((assigned.get("paging") or {}).get("cursors", {}).get("after") or "")
            if not page_accounts or not next_cursor:
                complete = True
                break
            if next_cursor == after or next_cursor in seen_cursors:
                raise HTTPException(
                    status_code=502,
                    detail="Meta returned a repeated pagination cursor while listing Instagram accounts. Please reconnect."
                )
            seen_cursors.add(next_cursor)
            after = next_cursor

        if not complete:
            raise HTTPException(
                status_code=502,
                detail="Meta returned too many Instagram assets to verify safely. Please contact support."
            )

        accounts = list(accounts_by_id.values())
        if not accounts:
            business_hint = (
                f" Meta business ID: {client_business_id}." if client_business_id else ""
            )
            raise HTTPException(
                status_code=400,
                detail=(
                    "Facebook authorization succeeded, but Meta returned zero Instagram accounts "
                    "for this login configuration. In the Facebook consent screen, select the "
                    "existing @prem.milan.app Instagram asset (do not create a Page or ad account), "
                    "then approve and reconnect. If it is already selected, verify the Instagram "
                    "account is Professional and owned by the same business portfolio, and check "
                    "that the saved configuration is the one used by this app." + business_hint
                )
            )
        if len(accounts) > 1:
            raise HTTPException(
                status_code=400,
                detail="More than one Instagram account is shared. Keep only the intended Instagram account selected in the Meta configuration, then reconnect."
            )

        ig_account = accounts[0]
        ig_user_id = str(ig_account.get("id") or "")
        username = str(ig_account.get("username") or "")
        if not ig_user_id:
            raise HTTPException(status_code=502, detail="Meta did not return an Instagram account ID.")

        # Confirm the selected account profile using the Unified Login Graph API.
        profile = instagram_http(instagram_graph_url(
            ig_user_id,
            fields="id,username",
            access_token=access_token
        ))
        username = str(profile.get("username") or username)
        ig_user_id = str(profile.get("id") or ig_user_id)
        if not username:
            raise HTTPException(status_code=502, detail="Instagram was authorized, but Meta did not return the account username.")

        encrypted = instagram_cipher().encrypt(access_token.encode("utf-8")).decode("ascii")
        now = datetime.now(timezone.utc).isoformat()
        expires_at = int(time.time()) + expires_in if expires_in > 0 else None
        with get_db() as conn:
            conn.execute("""
                INSERT INTO instagram_connections
                (instagram_user_id, username, account_type, encrypted_token, token_expires_at, connected_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(instagram_user_id) DO UPDATE SET
                  username=excluded.username, account_type=excluded.account_type,
                  encrypted_token=excluded.encrypted_token, token_expires_at=excluded.token_expires_at,
                  updated_at=excluded.updated_at
            """, (ig_user_id, username, "Professional", encrypted, expires_at, now, now))
            conn.commit()

        return instagram_frontend_redirect("connected", username=username)

    except HTTPException as exc:
        return instagram_frontend_redirect("error", message=str(exc.detail)[:240])


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

@app.post("/api/payments/trial/create")
def create_trial_subscription(data: CheckoutCustomer):
    """
    Single-checkout trial:
    - ₹1 upfront add-on is collected as part of subscription authorization.
    - ₹159/month plan starts 24 hours after subscription creation.
    - Customer approves the recurring UPI mandate in the same Razorpay Checkout.
    """
    if not RAZORPAY_PLAN_ID:
        raise HTTPException(status_code=503, detail="Razorpay monthly plan is not configured.")

    customer = {
        "name": clean_customer(data.name, 100),
        "email": clean_customer(data.email, 150),
        "contact": clean_customer(data.contact, 20)
    }

    first_charge_at = int(time.time()) + TRIAL_START_DELAY_SECONDS
    sub = razorpay_request("POST", "/subscriptions", {
        "plan_id": RAZORPAY_PLAN_ID,
        "total_count": 1200,
        "quantity": 1,
        "customer_notify": False,
        "start_at": first_charge_at,
        # Keep authorization open until shortly before the scheduled first cycle.
        "expire_by": first_charge_at - 60,
        # Razorpay collects this upfront amount as part of subscription authorization.
        "addons": [{
            "item": {
                "name": "InstaRaksha one-time trial payment",
                "amount": TRIAL_AMOUNT_PAISE,
                "currency": "INR"
            }
        }],
        "notes": {
            "plan_type": "trial_1_then_159",
            "customer_name": customer["name"],
            "upfront_amount_paise": str(TRIAL_AMOUNT_PAISE),
            "first_recurring_amount": "15900",
            "first_recurring_after_hours": "24"
        }
    })

    save_subscription(sub, "trial_1_then_159", customer, first_charge_at=first_charge_at)
    return {
        "subscription_id": sub["id"],
        "status": sub.get("status"),
        "start_at": sub.get("start_at", first_charge_at),
        "charge_at": sub.get("charge_at", first_charge_at),
        "upfront_amount": TRIAL_AMOUNT_PAISE,
        "recurring_amount": 15900,
        "currency": "INR",
        "key_id": RAZORPAY_KEY_ID
    }


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
    if sub.get("plan_id") != RAZORPAY_PLAN_ID:
        raise HTTPException(status_code=400, detail="Subscription does not match the configured ₹159/month plan.")
    payment = razorpay_request("GET", "/payments/" + data.razorpay_payment_id)
    if payment.get("subscription_id") and payment.get("subscription_id") != data.razorpay_subscription_id:
        raise HTTPException(status_code=400, detail="Authorization payment does not match this subscription.")
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
              "trial_1_then_159" if (sub.get("notes", {}).get("plan_type") == "trial_1_then_159" or sub.get("notes", {}).get("trial_order_id")) else "direct_159_monthly",
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
