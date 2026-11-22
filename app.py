import json
import os
import re
import sqlite3
import time
from collections import defaultdict
from functools import wraps
from flask import Flask, jsonify, make_response, render_template, request, session

app = Flask(__name__)

# مفتاح سري قوي للجلسات (يفضل وضعه في متغير بيئة SECRET_KEY عند الاستضافة)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
QUESTIONS_PATH = os.path.join(BASE_DIR, "questions.json")
DB_PATH = os.path.join(BASE_DIR, "exam_results.db")

# حماية بسيطة ضد كثرة الطلبات (Rate Limiting / Brute-force) حسب عنوان IP
RATE_LIMIT_WINDOW = 60  # ثانية
MAX_REQUESTS_PER_WINDOW = 60
request_log = defaultdict(list)


def rate_limited(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
        ip = ip.split(",")[0].strip()
        now = time.time()
        request_log[ip] = [t for t in request_log[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(request_log[ip]) >= MAX_REQUESTS_PER_WINDOW:
            return jsonify({"error": "Too many requests. Please slow down."}), 429
        request_log[ip].append(now)
        return f(*args, **kwargs)
    return decorated


@app.after_request
def add_security_headers(response):
    # حماية ضد XSS و Clickjacking و MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                submitted_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def load_questions():
    with open(QUESTIONS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or len(data) == 0:
        raise ValueError("questions.json must contain a non-empty list of questions.")
    return data


def sanitize_text(value, max_len=200):
    if not isinstance(value, str):
        return ""
    # إزالة أي وسوم HTML/Script لمنع XSS وتقليص الطول
    cleaned = re.sub(r"<[^>]*?>", "", value).strip()
    return cleaned[:max_len]


def evaluate_code_question(question_obj, student_code):
    if not isinstance(student_code, str):
        return False
    # تحديد حجم الكود المرسل لمنع أي إساءة استخدام
    if len(student_code) > 4000:
        return False
    required_tokens = question_obj.get("required_tokens", [])
    if not required_tokens:
        return False
    # فحص وجود العناصر الأساسية المطلوبة في الكود بدون تشغيل كود خطير على السيرفر
    return all(token in student_code for token in required_tokens)


@app.route("/")
@rate_limited
def index():
    session.setdefault("exam_started_at", time.time())
    return render_template("index.html")


@app.route("/api/questions", methods=["GET"])
@rate_limited
def get_questions():
    try:
        questions = load_questions()
    except Exception:
        return jsonify({"error": "Failed to load exam questions."}), 500

    # إخفاء الإجابات الصحيحة و required_tokens عن المتصفح أثناء الامتحان
    safe_questions = []
    for q in questions:
        safe_q = {
            "id": q.get("id"),
            "type": q.get("type"),
            "question": q.get("question"),
            "code": q.get("code", ""),
        }
        if q.get("type") == "mcq":
            safe_q["options"] = q.get("options", [])
        safe_questions.append(safe_q)

    return jsonify({"count": len(safe_questions), "questions": safe_questions})


@app.route("/api/submit", methods=["POST"])
@rate_limited
def submit_exam():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload."}), 400

    student_name = sanitize_text(data.get("student_name", "Anonymous"), max_len=80) or "Anonymous"
    answers = data.get("answers", {})
    if not isinstance(answers, dict):
        return jsonify({"error": "Answers must be an object."}), 400

    try:
        questions = load_questions()
    except Exception:
        return jsonify({"error": "Failed to load exam questions."}), 500

    score = 0
    total = len(questions)
    details = []

    for q in questions:
        qid = str(q.get("id"))
        qtype = q.get("type")
        user_ans = answers.get(qid, answers.get(q.get("id")))
        is_correct = False

        if qtype == "mcq":
            clean_ans = sanitize_text(user_ans, max_len=300) if isinstance(user_ans, str) else ""
            is_correct = clean_ans == q.get("answer")
        elif qtype == "write_code":
            is_correct = evaluate_code_question(q, user_ans)

        if is_correct:
            score += 1

        details.append({
            "id": q.get("id"),
            "correct": is_correct,
        })

    # حفظ النتيجة باستخدام Parameterized Query لمنع SQL Injection بشكل كامل
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO submissions (student_name, score, total, submitted_at) VALUES (?, ?, ?, ?)",
            (student_name, score, total, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())),
        )
        conn.commit()
    finally:
        conn.close()

    percentage = round((score / total) * 100, 2) if total > 0 else 0
    return jsonify({
        "student_name": student_name,
        "score": score,
        "total": total,
        "percentage": percentage,
        "details": details,
    })


@app.route("/robots.txt")
def robots_txt():
    content = "User-agent: *\nAllow: /\n"
    resp = make_response(content, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return resp


init_db()

if __name__ == "__main__":
    # تشغيل السيرفر محلياً أثناء التطوير بدون debug=True في الإنتاج
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
