from flask import Flask, request, jsonify
import os
import re
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

API_KEY = os.getenv("API_KEY")
LLM_API_KEY = os.getenv("LLM_API_KEY")

if not API_KEY:
    raise RuntimeError("API_KEY not set in .env")

if not LLM_API_KEY:
    raise RuntimeError("LLM_API_KEY not set in .env")

# 🔁 ONLY CHANGE: OpenAI → Hugging Face Router
client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=LLM_API_KEY
)

SYSTEM_PROMPT = """
You are a normal human user responding to messages.

Rules:
- You are not an AI.
- You do not know this is a scam.
- You are anxious and slightly confused.
- You respond politely and briefly.
- You ask clarifying questions.
- You do NOT accuse or threaten.
- You do NOT give real personal or financial information.
- You try to delay decisions.

Goal: Continue the conversation naturally.
"""

app = Flask(__name__)
sessions = {}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "today", "now",
    "blocked", "suspended", "deactivated"
]

FINANCIAL_KEYWORDS = [
    "bank", "upi", "refund", "otp",
    "verify", "kyc", "account"
]

PRESSURE_KEYWORDS = [
    "click", "link", "confirm", "avoid",
    "final", "last chance"
]

def detect_scam_intent(text: str) -> bool:
    if not text:
        return False

    text = text.lower()
    score = 0

    for w in URGENCY_KEYWORDS:
        if w in text:
            score += 2

    for w in FINANCIAL_KEYWORDS:
        if w in text:
            score += 2

    for w in PRESSURE_KEYWORDS:
        if w in text:
            score += 3

    return score >= 4

UPI_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b")
PHONE_REGEX = re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "blocked", "suspended",
    "refund", "otp", "click", "link", "kyc"
]

def extract_intelligence(text: str) -> dict:
    if not text:
        return {}

    found = {
        "bankAccounts": [],
        "upiIds": UPI_REGEX.findall(text),
        "phishingLinks": URL_REGEX.findall(text),
        "phoneNumbers": PHONE_REGEX.findall(text),
        "suspiciousKeywords": []
    }

    lower = text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            found["suspiciousKeywords"].append(kw)

    return found

def generate_llm_reply(conversation_history: list) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for msg in conversation_history:
        role = "assistant" if msg.get("sender") == "user" else "user"
        messages.append({
            "role": role,
            "content": msg.get("text", "")
        })

    # 🔁 ONLY CHANGE: model name
    completion = client.chat.completions.create(
        model="meta-llama/Llama-3.1-8B-Instruct:novita",
        messages=messages,
        max_tokens=150,
        temperature=0.7
    )

    return completion.choices[0].message.content.strip()

def should_terminate(session: dict) -> bool:
    if session.get("finalized"):
        return True

    if session.get("messageCount", 0) >= 15:
        return True

    intel = session.get("intelligence", {})
    signals = 0

    if intel.get("upiIds"):
        signals += 1
    if intel.get("phishingLinks"):
        signals += 1
    if intel.get("phoneNumbers"):
        signals += 1

    return signals >= 2

@app.route("/honeypot/message", methods=["GET", "POST"])
def honeypot_message():
    client_key = (
        request.headers.get("x-api-key") or
        request.headers.get("X-API-KEY") or
        request.headers.get("X-Api-Key") or
        request.args.get("api_key") or
        request.json.get("api_key") if request.is_json else None
    )

    print("DEBUG HEADER:", client_key)
    print("DEBUG ENV API_KEY:", API_KEY)

    if client_key != API_KEY:
        return jsonify({
            "status": "error",
            "message": "Unauthorized",
            "client_key": client_key,
            "API_KEY": API_KEY
        }), 401

    if request.method == "GET":
        return jsonify({
            "status": "success",
            "reply": "Honeypot endpoint is active and secured."
        }), 200

    data = request.get_json(silent=True) or {}

    if not data:
        return jsonify({
            "status": "success",
            "reply": "Honeypot endpoint is active and secured."
        }), 200

    return jsonify({
        "status": "success",
        "reply": "Authenticated request received."
    }), 200
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))
