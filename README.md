# 🔒 Streamzy - Secure Terminal Chat Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-green.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Flask-3.0-blue.svg" alt="Flask Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Security-E2E%20Encrypted-red.svg" alt="Security">
</p>

```
 ███████╗████████╗██████╗ ███████╗ █████╗ ███╗   ███╗███████╗██╗   ██╗
 ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗████╗ ████║╚══███╔╝╚██╗ ██╔╝
 ███████╗   ██║   ██████╔╝█████╗  ███████║██╔████╔██║  ███╔╝  ╚████╔╝ 
 ╚════██║   ██║   ██╔══██╗██╔══╝  ██╔══██║██║╚██╔╝██║ ███╔╝    ╚██╔╝  
 ███████║   ██║   ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗   ██║   
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   
```

A secure, private terminal-style chat platform with Matrix-inspired hacker aesthetics. Features end-to-end encryption, application-based registration, and real-time WebSocket communication.

## ✨ Features

### Security
- 🔐 **End-to-end message encryption** using Fernet (AES-128-CBC)
- 🔑 **Bcrypt password hashing** with configurable rounds
- 🛡️ **CSRF protection** on all forms
- 🚫 **SQL injection protection** with parameterized queries
- 🧹 **XSS prevention** with input sanitization
- ⏱️ **Session management** with automatic timeout
- 📊 **Rate limiting** to prevent abuse
- 📝 **Security audit logging**

### Access Control
- 📧 **Application-based registration** - no open signups
- 🎲 **Auto-generated credentials** sent via email
- 👮 **Admin approval required** for new users
- 🚪 **Private platform** - only accessible when server is running

### Terminal Interface
- 💚 **Matrix-green terminal aesthetic**
- ⌨️ **Command-line interface** with history
- 💬 **Real-time messaging** via WebSockets
- 👥 **Online user list**
- ⚡ **Typing indicators**
- 🖥️ **CRT/scanline effects**

### Admin Features
- 📋 **Application management** (approve/reject)
- 👤 **User management** (enable/disable)
- 📊 **Audit log viewer**
- 📈 **System monitoring**

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)
- (Optional) Virtual environment

### Installation

1. **Clone or navigate to the project directory:**
```bash
cd /path/to/streamzy
```

2. **Create and activate a virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables:**
```bash
cp .env.example .env
# Edit .env with your settings
```

5. **Generate encryption key:**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Copy the output to ENCRYPTION_KEY in .env
```

6. **Generate secret key:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
# Copy the output to SECRET_KEY in .env
```

7. **Run the server:**
```bash
python app.py
```

8. **Access the platform:**
- Open: http://localhost:5000
- Default admin login:
  - Username: `admin`
  - Password: `changeme123!`

⚠️ **IMPORTANT:** Change the admin password immediately after first login!

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# Flask Configuration
SECRET_KEY=your-secret-key-here
FLASK_ENV=development  # or 'production'
FLASK_DEBUG=0

# Encryption
ENCRYPTION_KEY=your-fernet-key-here

# Email (for sending credentials)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=Streamzy <your-email@gmail.com>
```

### Email Setup (Gmail)

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password:
   - Go to Google Account → Security → App passwords
   - Generate a new app password for "Mail"
   - Use this password in `MAIL_PASSWORD`

## 📖 Usage

### User Registration Flow

1. User visits `/apply` and submits email
2. Admin approves application in admin panel (`/admin`)
3. System generates username and password
4. Credentials are sent to user's email
5. User logs in at `/login`
6. User can now chat!

### Chat Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/users` | List online users |
| `/rooms` | List available rooms |
| `/join <room>` | Join a specific room |
| `/clear` | Clear terminal screen |
| `/whoami` | Display your username |
| `/time` | Show server time |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Enter` | Send message |
| `↑` / `↓` | Navigate command history |
| `Tab` | Autocomplete commands |
| `Escape` | Clear input |

## 🏗️ Project Structure

```
streamzy/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings
├── models.py              # Database models
├── encryption.py          # Encryption utilities
├── email_service.py       # Email sending service
├── security.py            # Security middleware
├── requirements.txt       # Python dependencies
├── .env.example           # Environment template
├── templates/
│   ├── base.html          # Base template
│   ├── login.html         # Login page
│   ├── apply.html         # Application page
│   ├── chat.html          # Main chat interface
│   ├── admin.html         # Admin panel
│   ├── 404.html           # Error page
│   └── 500.html           # Error page
└── static/
    ├── css/
    │   ├── terminal.css   # Terminal styling
    │   ├── chat.css       # Chat-specific styles
    │   └── admin.css      # Admin panel styles
    └── js/
        ├── terminal.js    # Terminal utilities
        └── chat.js        # Chat client
```

## 🔒 Security Considerations

### Production Deployment

1. **Use HTTPS** - Required for secure WebSocket connections
2. **Set `SESSION_COOKIE_SECURE=True`** in production
3. **Use a proper WSGI server** (Gunicorn with eventlet/gevent)
4. **Configure firewall** to only expose necessary ports
5. **Use environment variables** for all secrets
6. **Regular security audits** - check audit logs
7. **Database backups** - regularly backup `streamzy.db`

### Running in Production

```bash
# With Gunicorn and eventlet
gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:5000 app:app

# With Gunicorn and gevent
gunicorn --worker-class gevent -w 1 -b 0.0.0.0:5000 app:app
```

### Nginx Reverse Proxy Example

```nginx
server {
    listen 443 ssl;
    server_name streamzy.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 🐛 Troubleshooting

### Common Issues

**Email not sending:**
- Check SMTP credentials in `.env`
- For Gmail, ensure you're using an App Password
- Check firewall allows outbound port 587

**WebSocket connection fails:**
- Ensure eventlet or gevent is installed
- Check CORS settings if using different domains
- Verify WebSocket upgrade is supported by proxy

**Database errors:**
- Delete `streamzy.db` and restart to recreate
- Check file permissions on database directory

**Import errors:**
- Ensure virtual environment is activated
- Run `pip install -r requirements.txt` again

## 📄 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This software is provided for educational and authorized use only. Users are responsible for ensuring compliance with all applicable laws and regulations. The developers are not responsible for any misuse of this software.

---

<p align="center">
  <strong>🔒 Stay Secure. Stay Private. 🔒</strong>
</p>
