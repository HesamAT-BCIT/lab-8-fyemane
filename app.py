from __future__ import annotations

import os
from typing import Any, Optional, Tuple, Union

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

import firebase_admin
from firebase_admin import auth, credentials, firestore

# -----------------------------
# App + Env
# -----------------------------
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")
if not WEB_API_KEY:
    raise RuntimeError("Missing FIREBASE_WEB_API_KEY in .env")

# -----------------------------
# Firebase Admin SDK
# -----------------------------
if not firebase_admin._apps:
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT", "serviceAccountKey.json")
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

# -----------------------------
# Helpers
# -----------------------------
def require_json_content_type():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None


def get_profile_doc_ref(uid: str):
    return db.collection("profiles").document(uid)


def get_profile_data(uid: str) -> dict[str, Any]:
    doc = get_profile_doc_ref(uid).get()
    return doc.to_dict() if doc.exists else {}


def set_profile(uid: str, profile_data: dict[str, Any], *, merge: bool):
    get_profile_doc_ref(uid).set(profile_data, merge=merge)


def validate_profile_data(first_name: str, last_name: str, student_id: str) -> Optional[str]:
    if not first_name or not last_name or not student_id:
        return "All fields are required."
    return None


def normalize_profile_data(first_name: str, last_name: str, student_id: str) -> dict[str, str]:
    return {
        "first_name": first_name.strip() if first_name else "",
        "last_name": last_name.strip() if last_name else "",
        "student_id": str(student_id).strip() if student_id else "",
    }


def verify_bearer_token() -> Union[str, Tuple[Any, int]]:
    """Verify JWT from Authorization header; return uid or (json, code)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split("Bearer ", 1)[1].strip()
    if not token:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        decoded = auth.verify_id_token(token)
        return decoded["uid"]
    except Exception:
        return jsonify({"error": "Unauthorized"}), 401


def get_web_user_uid() -> Optional[str]:
    """For HTML pages: verify the idToken stored in the session and return uid."""
    token = session.get("idToken")
    if not token:
        return None
    try:
        decoded = auth.verify_id_token(token)
        return decoded["uid"]
    except Exception:
        session.clear()
        return None


def firebase_sign_in(email: str, password: str) -> Union[dict[str, Any], None]:
    """Use Firebase Identity Toolkit to login with email/password and get idToken."""
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    res = requests.post(url, json=payload, timeout=10)
    if res.status_code == 200:
        return res.json()
    return None


# -----------------------------
# Web Routes
# -----------------------------
@app.route("/")
def home():
    uid = get_web_user_uid()
    if not uid:
        return redirect(url_for("login"))

    profile = get_profile_data(uid)
    # show email if we stored it; fallback to uid
    display_name = profile.get("email") or uid
    return render_template("dashboard.html", username=display_name)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not email or not password:
        return render_template("signup.html", error="Email and password are required.")
    if password != confirm_password:
        return render_template("signup.html", error="Passwords do not match.")

    try:
        user = auth.create_user(email=email, password=password)
        # Initialize profile in Firestore (uid as doc id)
        set_profile(user.uid, {"email": email, "role": "user"}, merge=False)
        return redirect(url_for("login"))
    except Exception as e:
        return render_template("signup.html", error=f"Signup failed: {e}")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("login.html", error="Email and password are required.")

    auth_res = firebase_sign_in(email, password)
    if not auth_res:
        return render_template("login.html", error="Invalid credentials. Try again.")

    # Store idToken for HTML routes
    session["idToken"] = auth_res["idToken"]
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    uid = get_web_user_uid()
    if not uid:
        return redirect(url_for("login"))

    if request.method == "GET":
        profile_data = get_profile_data(uid)
        return render_template("profile.html", profile=profile_data, error=None)

    first_name = request.form.get("first_name", "")
    last_name = request.form.get("last_name", "")
    student_id = request.form.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        profile_data = {"first_name": first_name, "last_name": last_name, "student_id": student_id}
        return render_template("profile.html", profile=profile_data, error=error)

    normalized = normalize_profile_data(first_name, last_name, student_id)
    # keep existing email/role; merge profile fields
    set_profile(uid, normalized, merge=True)
    return redirect(url_for("home"))


# -----------------------------
# API Routes (JWT protected)
# -----------------------------
@app.post("/api/signup")
def api_signup():
    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    try:
        user = auth.create_user(email=email, password=password)
        set_profile(user.uid, {"email": email, "role": "user"}, merge=False)
        return jsonify({"message": "User created", "uid": user.uid}), 201
    except Exception as e:
        return jsonify({"error": f"Signup failed: {e}"}), 400


@app.post("/api/login")
def api_login():
    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    auth_res = firebase_sign_in(email, password)
    if not auth_res:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"token": auth_res["idToken"]}), 200


@app.get("/api/profile")
def api_get_profile():
    uid_or_resp = verify_bearer_token()
    if not isinstance(uid_or_resp, str):
        return uid_or_resp
    uid = uid_or_resp

    profile_data = get_profile_data(uid)
    return jsonify({"uid": uid, "profile": profile_data}), 200


@app.post("/api/profile")
def api_create_profile():
    uid_or_resp = verify_bearer_token()
    if not isinstance(uid_or_resp, str):
        return uid_or_resp
    uid = uid_or_resp

    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")
    student_id = data.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        return jsonify({"error": error}), 400

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(uid, normalized, merge=True)
    return jsonify({"message": "Profile saved successfully", "profile": get_profile_data(uid)}), 200


@app.put("/api/profile")
def api_update_profile():
    # Task 3 hardening happens later; Task 1 just needs JWT auth working.
    uid_or_resp = verify_bearer_token()
    if not isinstance(uid_or_resp, str):
        return uid_or_resp
    uid = uid_or_resp

    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Request body cannot be empty"}), 400

    update_data: dict[str, Any] = {}
    if "first_name" in data:
        update_data["first_name"] = str(data["first_name"]).strip()
    if "last_name" in data:
        update_data["last_name"] = str(data["last_name"]).strip()
    if "student_id" in data:
        update_data["student_id"] = str(data["student_id"]).strip()

    if not update_data:
        return jsonify({"error": "No updatable fields provided"}), 400

    set_profile(uid, update_data, merge=True)
    return jsonify({"message": "Profile updated successfully", "profile": get_profile_data(uid)}), 200


@app.delete("/api/profile")
def api_delete_profile():
    uid_or_resp = verify_bearer_token()
    if not isinstance(uid_or_resp, str):
        return uid_or_resp
    uid = uid_or_resp

    get_profile_doc_ref(uid).delete()
    return jsonify({"message": "Profile deleted successfully"}), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)