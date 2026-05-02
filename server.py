from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import JSONResponse, FileResponse
import sqlite3
import hashlib
import time
import os

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
LATEST_DIR = os.path.join(BASE_DIR, "latest")

os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(LATEST_DIR, exist_ok=True)

APP_VERSION = "1.0.0"


# ================= 공통 =================

def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def today_text():
    return time.strftime("%Y-%m-%d")


def hash_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def connect_db():
    return sqlite3.connect(DB_PATH)


def split_pc_hashes(value):
    value = str(value or "").strip()
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def join_pc_hashes(items):
    return ",".join([str(x).strip() for x in items if str(x).strip()])


# ================= DB =================

def init_db():
    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        password_hash TEXT DEFAULT '',
        password_plain TEXT DEFAULT '',
        pc_hash TEXT DEFAULT '',
        expire_date TEXT DEFAULT '',
        active INTEGER DEFAULT 1,
        last_seen TEXT DEFAULT '',
        last_ip TEXT DEFAULT '',
        target_title TEXT DEFAULT '',
        capture_requested INTEGER DEFAULT 0,
        memo TEXT DEFAULT '',
        max_devices INTEGER DEFAULT 1
    )
    """)

    cur.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cur.fetchall()]

    add_cols = {
        "password_hash": "TEXT DEFAULT ''",
        "password_plain": "TEXT DEFAULT ''",
        "pc_hash": "TEXT DEFAULT ''",
        "expire_date": "TEXT DEFAULT ''",
        "active": "INTEGER DEFAULT 1",
        "last_seen": "TEXT DEFAULT ''",
        "last_ip": "TEXT DEFAULT ''",
        "target_title": "TEXT DEFAULT ''",
        "capture_requested": "INTEGER DEFAULT 0",
        "memo": "TEXT DEFAULT ''",
        "max_devices": "INTEGER DEFAULT 1",
    }

    for col, col_type in add_cols.items():
        if col not in cols:
            try:
                cur.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
            except Exception:
                pass

    conn.commit()
    conn.close()


init_db()


# ================= 요청 파싱 =================

async def read_params(request: Request):
    data = {}

    try:
        form = await request.form()
        for k, v in form.items():
            data[k] = v
    except Exception:
        pass

    try:
        js = await request.json()
        if isinstance(js, dict):
            data.update(js)
    except Exception:
        pass

    try:
        for k, v in request.query_params.items():
            data[k] = v
    except Exception:
        pass

    return data


# ================= 기본 =================

@app.get("/")
def root():
    return {"ok": True, "msg": "license server running"}


# ================= 로그인 =================

@app.post("/login")
async def login(request: Request):
    data = await read_params(request)

    user_id = str(data.get("user_id", "")).strip()
    password = str(data.get("password", "")).strip()
    pc_hash = str(data.get("pc_hash", "")).strip()
    target_title = str(data.get("target_title", "")).strip()

    if not user_id or not password:
        return {"success": False, "msg": "아이디/비밀번호 누락"}

    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT password_hash, pc_hash, expire_date, active, max_devices
    FROM users
    WHERE user_id=?
    """, (user_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return {"success": False, "msg": "아이디 없음"}

    db_pw_hash, db_pc_hash, expire_date, active, max_devices = row

    try:
        max_devices = max(1, int(max_devices or 1))
    except Exception:
        max_devices = 1

    if hash_text(password) != str(db_pw_hash):
        conn.close()
        return {"success": False, "msg": "비밀번호 틀림"}

    if int(active or 0) != 1:
        conn.close()
        return {"success": False, "msg": "사용 중지 계정"}

    if expire_date and today_text() > str(expire_date):
        conn.close()
        return {"success": False, "msg": "사용 기간 만료"}

    pc_list = split_pc_hashes(db_pc_hash)

    if pc_hash:
        if pc_hash in pc_list:
            pass
        else:
            if len(pc_list) >= max_devices:
                conn.close()
                return {"success": False, "msg": f"허용 PC 수 초과 ({max_devices}대)"}
            pc_list.append(pc_hash)
            cur.execute("UPDATE users SET pc_hash=? WHERE user_id=?", (join_pc_hashes(pc_list), user_id))

    client_ip = request.client.host if request.client else ""

    cur.execute("""
    UPDATE users
    SET last_seen=?, last_ip=?, target_title=?
    WHERE user_id=?
    """, (now_text(), client_ip, target_title, user_id))

    conn.commit()
    conn.close()

    return {"success": True, "msg": "로그인 성공"}


# ================= heartbeat =================

@app.post("/heartbeat")
async def heartbeat(request: Request):
    data = await read_params(request)

    user_id = str(data.get("user_id", "")).strip()
    pc_hash = str(data.get("pc_hash", "")).strip()
    target_title = str(data.get("target_title", "")).strip()

    if not user_id:
        return {"ok": False, "active": 0, "msg": "user_id 누락"}

    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT pc_hash, active, expire_date, capture_requested
    FROM users
    WHERE user_id=?
    """, (user_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return {"ok": False, "active": 0, "msg": "아이디 없음"}

    db_pc_hash, active, expire_date, capture_requested = row

    pc_list = split_pc_hashes(db_pc_hash)
    if pc_hash and pc_list and pc_hash not in pc_list:
        conn.close()
        return {"ok": False, "active": 0, "msg": "등록되지 않은 PC"}

    if expire_date and today_text() > str(expire_date):
        conn.close()
        return {"ok": True, "active": 0, "msg": "사용 기간 만료"}

    client_ip = request.client.host if request.client else ""

    cur.execute("""
    UPDATE users
    SET last_seen=?, last_ip=?, target_title=?
    WHERE user_id=?
    """, (now_text(), client_ip, target_title, user_id))

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "active": int(active or 0),
        "capture_requested": int(capture_requested or 0),
        "msg": "ok"
    }


# ================= 캡쳐 =================

@app.post("/clear_capture_request")
async def clear_capture_request(request: Request):
    data = await read_params(request)
    user_id = str(data.get("user_id", "")).strip()

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET capture_requested=0 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    return {"success": True}


@app.post("/upload_capture")
async def upload_capture(request: Request, file: UploadFile = File(...)):
    data = await read_params(request)
    user_id = str(data.get("user_id", "")).strip()

    if not user_id:
        return {"success": False, "msg": "user_id 누락"}

    path = os.path.join(CAPTURE_DIR, f"{user_id}.png")

    with open(path, "wb") as f:
        f.write(await file.read())

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET capture_requested=0 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    return {"success": True, "path": path}


@app.get("/get_capture/{user_id}")
def get_capture(user_id: str):
    path = os.path.join(CAPTURE_DIR, f"{user_id}.png")
    if os.path.exists(path):
        return FileResponse(path, media_type="image/png")
    return JSONResponse({"error": "no image"}, status_code=404)


# ================= 관리자 =================

@app.get("/users")
def users():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
    SELECT user_id, expire_date, active, last_seen, pc_hash, target_title,
           capture_requested, memo, max_devices, password_plain
    FROM users
    ORDER BY user_id
    """)
    rows = cur.fetchall()
    conn.close()

    result = []
    for r in rows:
        pc_list = split_pc_hashes(r[4])
        result.append({
            "user_id": r[0],
            "expire_date": r[1],
            "active": r[2],
            "last_seen": r[3],
            "pc_hash": r[4],
            "pc_count": len(pc_list),
            "target_title": r[5],
            "capture_requested": r[6],
            "memo": r[7],
            "max_devices": r[8] if r[8] is not None else 1,
            "password_plain": r[9] or "",
        })

    return {"users": result}


@app.post("/admin/create_user")
async def admin_create_user(request: Request):
    data = await read_params(request)

    user_id = str(data.get("user_id", "")).strip()
    password = str(data.get("password", "")).strip()
    expire_date = str(data.get("expire_date", "")).strip()
    memo = str(data.get("memo", "")).strip()

    try:
        max_devices = max(1, int(data.get("max_devices", 1)))
    except Exception:
        max_devices = 1

    if not user_id or not password:
        return {"success": False, "msg": "아이디/비밀번호 누락"}

    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
    INSERT OR REPLACE INTO users
    (user_id, password_hash, password_plain, pc_hash, expire_date, active, last_seen,
     last_ip, target_title, capture_requested, memo, max_devices)
    VALUES (?, ?, ?, '', ?, 1, '', '', '', 0, ?, ?)
    """, (user_id, hash_text(password), password, expire_date, memo, max_devices))

    conn.commit()
    conn.close()

    return {"success": True}


@app.post("/admin/update_user")
async def admin_update_user(request: Request):
    data = await read_params(request)

    user_id = str(data.get("user_id", "")).strip()
    password = str(data.get("password", "")).strip()
    expire_date = str(data.get("expire_date", "")).strip()
    memo = str(data.get("memo", "")).strip()

    try:
        max_devices = max(1, int(data.get("max_devices", 1)))
    except Exception:
        max_devices = 1

    if not user_id:
        return {"success": False, "msg": "user_id 누락"}

    conn = connect_db()
    cur = conn.cursor()

    if password:
        cur.execute("""
        UPDATE users
        SET password_hash=?, password_plain=?, expire_date=?, memo=?, max_devices=?
        WHERE user_id=?
        """, (hash_text(password), password, expire_date, memo, max_devices, user_id))
    else:
        cur.execute("""
        UPDATE users
        SET expire_date=?, memo=?, max_devices=?
        WHERE user_id=?
        """, (expire_date, memo, max_devices, user_id))

    conn.commit()
    conn.close()

    return {"success": True}


@app.post("/admin/set_active")
async def admin_set_active(request: Request):
    data = await read_params(request)

    user_id = str(data.get("user_id", "")).strip()
    active = int(data.get("active", 0))

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET active=? WHERE user_id=?", (active, user_id))
    conn.commit()
    conn.close()

    return {"success": True}


@app.post("/admin/reset_pc")
async def admin_reset_pc(request: Request):
    data = await read_params(request)
    user_id = str(data.get("user_id", "")).strip()

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET pc_hash='' WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    return {"success": True}


@app.post("/admin/set_max_devices")
async def admin_set_max_devices(request: Request):
    data = await read_params(request)

    user_id = str(data.get("user_id", "")).strip()
    try:
        max_devices = max(1, int(data.get("max_devices", 1)))
    except Exception:
        max_devices = 1

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET max_devices=? WHERE user_id=?", (max_devices, user_id))
    conn.commit()
    conn.close()

    return {"success": True}


@app.post("/admin/delete_user")
async def admin_delete_user(request: Request):
    data = await read_params(request)
    user_id = str(data.get("user_id", "")).strip()

    if not user_id:
        return {"success": False, "msg": "user_id 누락"}

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    capture_path = os.path.join(CAPTURE_DIR, f"{user_id}.png")
    try:
        if os.path.exists(capture_path):
            os.remove(capture_path)
    except Exception:
        pass

    return {"success": True}


@app.post("/admin/request_capture")
async def admin_request_capture(request: Request):
    data = await read_params(request)
    user_id = str(data.get("user_id", "")).strip()

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET capture_requested=1 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    return {"success": True}


# ================= 업데이트 =================

@app.get("/version")
def version():
    return {"version": APP_VERSION}


@app.get("/download")
def download():
    path = os.path.join(LATEST_DIR, "shot.exe")
    if not os.path.exists(path):
        return JSONResponse({"error": "latest shot.exe not found"}, status_code=404)
    return FileResponse(path, media_type="application/octet-stream", filename="shot.exe")
