import os
import re
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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