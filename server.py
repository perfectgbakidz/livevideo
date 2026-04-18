"""
FastAPI Video Receiver & Playback Server for Render Deployment
Fixed CORS and route issues
"""

import os
import sqlite3
import hashlib
import datetime
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, Request, File, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import argon2

# ==================== CONFIGURATION ====================

DATABASE = "/tmp/videos.db"
VIDEO_STORAGE = "/tmp/video_storage"
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

os.makedirs(VIDEO_STORAGE, exist_ok=True)

# ==================== DATABASE SETUP ====================

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            file_size INTEGER,
            recorded_date DATE NOT NULL,
            recorded_time TIME NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_videos_date ON videos(recorded_date)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_videos_device ON videos(device_id)')
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ==================== PASSWORD HASHING ====================

ph = argon2.PasswordHasher(time_cost=2, memory_cost=65536, parallelism=1)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, hash: str) -> bool:
    try:
        ph.verify(hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

# ==================== AUTHENTICATION ====================

security = HTTPBearer()

class TokenManager:
    def __init__(self):
        self.tokens = {}
    
    def create_token(self, username: str) -> str:
        token = hashlib.sha256(f"{username}{datetime.datetime.now().isoformat()}{SECRET_KEY}".encode()).hexdigest()
        self.tokens[token] = {
            "username": username,
            "created": datetime.datetime.now()
        }
        return token
    
    def verify_token(self, token: str) -> Optional[str]:
        if token in self.tokens:
            age = datetime.datetime.now() - self.tokens[token]["created"]
            if age.total_seconds() < 86400:
                return self.tokens[token]["username"]
            else:
                del self.tokens[token]
        return None

token_manager = TokenManager()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    username = token_manager.verify_token(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username

# ==================== PYDANTIC MODELS ====================

class LoginRequest(BaseModel):
    username: str
    password: str

# ==================== FASTAPI APP ====================

app = FastAPI(
    title="ESP32-CAM Video Server",
    description="Receive and store videos from ESP32-CAM",
    version="1.0.0"
)

# CRITICAL: CORS must be added BEFORE routes
# Allow all origins for ESP32-CAM access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

@app.on_event("startup")
async def startup():
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (ADMIN_USERNAME,))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD))
        )
        conn.commit()
        print(f"Created default user: {ADMIN_USERNAME}")
    conn.close()

# ==================== HTML PAGES ====================

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Video Server Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-box {
            background: rgba(255,255,255,0.95);
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 90%;
            max-width: 400px;
        }
        h2 { color: #1e3c72; margin-bottom: 1.5rem; text-align: center; }
        .input-group { margin-bottom: 1.2rem; }
        label { display: block; margin-bottom: 0.5rem; color: #555; font-size: 0.9rem; }
        input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 1rem;
        }
        input:focus { outline: none; border-color: #2a5298; }
        button {
            width: 100%;
            padding: 0.75rem;
            background: #2a5298;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
        }
        button:hover { background: #1e3c72; }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-top: 1rem;
            display: none;
        }
        .error.show { display: block; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔒 Video Server Login</h2>
        <form id="loginForm">
            <div class="input-group">
                <label>Username</label>
                <input type="text" id="username" required>
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" id="password" required>
            </div>
            <button type="submit">Sign In</button>
            <div class="error" id="error">Invalid credentials</div>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            });
            if (res.ok) {
                const data = await res.json();
                localStorage.setItem('token', data.token);
                window.location.href = '/dashboard';
            } else {
                document.getElementById('error').classList.add('show');
            }
        });
    </script>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Video Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f0f;
            color: #fff;
            min-height: 100vh;
        }
        .navbar {
            background: rgba(0,0,0,0.8);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .logo { font-size: 1.5rem; font-weight: 700; }
        button {
            background: #2a5298;
            color: #fff;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
        }
        button.danger { background: #e74c3c; }
        .container { padding: 2rem; max-width: 1400px; margin: 0 auto; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: 700; color: #27ae60; }
        .stat-label { color: #888; margin-top: 0.5rem; }
        .date-section {
            margin-bottom: 2rem;
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 1.5rem;
        }
        .date-header {
            font-size: 1.3rem;
            color: #667eea;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid rgba(102,126,234,0.3);
        }
        .video-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
        }
        .video-card {
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            overflow: hidden;
        }
        .video-card img {
            width: 100%;
            height: 200px;
            object-fit: cover;
            background: #000;
            cursor: pointer;
        }
        .video-info {
            padding: 1rem;
            font-size: 0.9rem;
        }
        .video-info div { margin: 0.25rem 0; color: #aaa; }
        .video-info span { color: #fff; }
        .empty-state { text-align: center; padding: 4rem; color: #888; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="logo">📹 ESP32-CAM Server</div>
        <div>
            <span id="userInfo">Loading...</span>
            <button onclick="loadVideos()" style="margin: 0 0.5rem">🔄 Refresh</button>
            <button onclick="logout()" class="danger">Logout</button>
        </div>
    </nav>
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="totalVideos">0</div>
                <div class="stat-label">Total Videos</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalDays">0</div>
                <div class="stat-label">Recording Days</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="todayVideos">0</div>
                <div class="stat-label">Today</div>
            </div>
        </div>
        <div id="videosContainer"><div class="empty-state">Loading...</div></div>
    </div>
    <script>
        const token = localStorage.getItem('token');
        if (!token) window.location.href = '/login';
        
        async function apiFetch(url, opts = {}) {
            opts.headers = { ...opts.headers, 'Authorization': `Bearer ${token}` };
            const res = await fetch(url, opts);
            if (res.status === 401) { logout(); return null; }
            return res;
        }
        
        async function loadUser() {
            const res = await apiFetch('/api/me');
            if (res) {
                const data = await res.json();
                document.getElementById('userInfo').textContent = `👤 ${data.username}`;
            }
        }
        
        async function loadVideos() {
            const container = document.getElementById('videosContainer');
            container.innerHTML = '<div class="empty-state">Loading...</div>';
            
            const res = await apiFetch('/api/videos');
            if (!res) return;
            const data = await res.json();
            
            document.getElementById('totalVideos').textContent = data.total_videos;
            document.getElementById('totalDays').textContent = Object.keys(data.videos_by_date).length;
            const today = new Date().toISOString().split('T')[0];
            document.getElementById('todayVideos').textContent = data.videos_by_date[today]?.length || 0;
            
            if (Object.keys(data.videos_by_date).length === 0) {
                container.innerHTML = '<div class="empty-state"><h2>No videos yet</h2><p>Videos will appear here when your ESP32-CAM sends them</p></div>';
                return;
            }
            
            container.innerHTML = '';
            const sortedDates = Object.keys(data.videos_by_date).sort().reverse();
            
            sortedDates.forEach(date => {
                const videos = data.videos_by_date[date];
                const section = document.createElement('div');
                section.className = 'date-section';
                const dateObj = new Date(date);
                section.innerHTML = `
                    <div class="date-header">${dateObj.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</div>
                    <div class="video-grid" id="grid-${date}"></div>
                `;
                container.appendChild(section);
                const grid = document.getElementById(`grid-${date}`);
                
                videos.forEach(video => {
                    const card = document.createElement('div');
                    card.className = 'video-card';
                    card.innerHTML = `
                        <img src="/api/videos/${video.id}/stream?token=${token}" 
                             onclick="window.open(this.src, '_blank')" 
                             alt="${video.filename}">
                        <div class="video-info">
                            <div>Time: <span>${video.recorded_time}</span></div>
                            <div>Device: <span>${video.device_id}</span></div>
                            <div>Size: <span>${formatBytes(video.file_size)}</span></div>
                        </div>
                    `;
                    grid.appendChild(card);
                });
            });
        }
        
        function formatBytes(bytes) {
            if (!bytes) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function logout() {
            localStorage.removeItem('token');
            window.location.href = '/login';
        }
        
        loadUser();
        loadVideos();
        setInterval(loadVideos, 30000);
    </script>
</body>
</html>
"""

# ==================== ROUTES ====================

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(content=LOGIN_PAGE)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    return HTMLResponse(content=DASHBOARD_PAGE)

@app.get("/")
async def root():
    return RedirectResponse(url="/login")

# CRITICAL: Add OPTIONS handler for CORS preflight
@app.options("/api/upload/frame")
async def options_upload_frame():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

@app.post("/api/login")
async def api_login(creds: LoginRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (creds.username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not verify_password(creds.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"token": token_manager.create_token(user["username"]), "username": user["username"]}

@app.get("/api/me")
async def api_me(username: str = Depends(get_current_user)):
    return {"username": username}

@app.post("/api/upload/frame")
async def upload_frame(request: Request):
    """Receive raw JPEG frame from ESP32-CAM"""
    try:
        body = await request.body()
        
        # Debug logging
        print(f"Received frame: {len(body)} bytes")
        print(f"Headers: {dict(request.headers)}")
        
        if len(body) < 100:
            raise HTTPException(status_code=400, detail="Invalid image data - too small")
        
        headers = request.headers
        device_id = headers.get("x-device-id", "esp32-cam-001")
        timestamp_str = headers.get("x-timestamp")
        resolution = headers.get("x-resolution", "unknown")
        
        # Parse timestamp
        if timestamp_str:
            try:
                # Handle ISO format with Z
                timestamp_str = timestamp_str.replace('Z', '+00:00')
                timestamp = datetime.datetime.fromisoformat(timestamp_str)
            except Exception as e:
                print(f"Timestamp parse error: {e}, using now")
                timestamp = datetime.datetime.now()
        else:
            timestamp = datetime.datetime.now()
        
        # Ensure timestamp is timezone-naive for storage
        if timestamp.tzinfo:
            timestamp = timestamp.replace(tzinfo=None)
        
        date_folder = timestamp.strftime("%Y-%m-%d")
        time_str = timestamp.strftime("%H-%M-%S-%f")[:-3]
        filename = f"{device_id}_{time_str}.jpg"
        
        storage_dir = os.path.join(VIDEO_STORAGE, date_folder)
        os.makedirs(storage_dir, exist_ok=True)
        storage_path = os.path.join(storage_dir, filename)
        
        with open(storage_path, "wb") as f:
            f.write(body)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO videos (device_id, filename, storage_path, file_size, recorded_date, recorded_time, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id, 
            filename, 
            storage_path, 
            len(body), 
            timestamp.date().isoformat(),
            timestamp.time().isoformat(), 
            f"{{'resolution': '{resolution}', 'source': 'esp32-cam'}}"
        ))
        video_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"Saved video {video_id}: {filename} ({len(body)} bytes)")
        
        return JSONResponse(
            content={
                "success": True, 
                "id": video_id, 
                "filename": filename,
                "size": len(body)
            },
            headers={"Access-Control-Allow-Origin": "*"}
        )
        
    except Exception as e:
        print(f"Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/videos")
async def list_videos(username: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, device_id, filename, file_size, recorded_date, recorded_time, created_at
        FROM videos ORDER BY recorded_date DESC, recorded_time DESC
    """)
    videos = cursor.fetchall()
    conn.close()
    
    videos_by_date = {}
    for video in videos:
        date = video["recorded_date"]
        if date not in videos_by_date:
            videos_by_date[date] = []
        videos_by_date[date].append({
            "id": video["id"], 
            "device_id": video["device_id"],
            "filename": video["filename"], 
            "file_size": video["file_size"],
            "recorded_time": video["recorded_time"], 
            "created_at": video["created_at"]
        })
    
    return {"total_videos": len(videos), "videos_by_date": videos_by_date}

@app.get("/api/videos/{video_id}/stream")
async def stream_video(video_id: int, token: Optional[str] = None, username: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM videos WHERE id = ?", (video_id,))
    video = cursor.fetchone()
    conn.close()
    
    if not video:
        raise HTTPException(status_code=404, detail="Video not found in database")
    
    if not os.path.exists(video["storage_path"]):
        raise HTTPException(status_code=404, detail="Video file not found on disk")
    
    def iterfile():
        with open(video["storage_path"], "rb") as f:
            yield from f
    
    return StreamingResponse(
        iterfile(), 
        media_type="image/jpeg",
        headers={
            "Cache-Control": "no-cache",
            "Access-Control-Allow-Origin": "*"
        }
    )

# Health check endpoint for Render
@app.get("/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
