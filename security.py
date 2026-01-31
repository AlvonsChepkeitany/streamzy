"""
Security utilities and middleware for Streamzy Chat Platform
"""
import re
import html
import functools
from datetime import datetime, timedelta, timezone
from flask import session, request, jsonify, current_app
import logging

logger = logging.getLogger(__name__)


class InputValidator:
    """Validate and sanitize user inputs"""
    
    # Email regex pattern
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    # Username pattern (alphanumeric, underscore, 3-50 chars)
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
    
    # SQL injection patterns to detect
    SQL_PATTERNS = [
        re.compile(r'(\%27)|(\')|(\-\-)|(\%23)|(#)', re.IGNORECASE),
        re.compile(r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))', re.IGNORECASE),
        re.compile(r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', re.IGNORECASE),
        re.compile(r'((\%27)|(\'))union', re.IGNORECASE),
        re.compile(r'exec(\s|\+)+(s|x)p\w+', re.IGNORECASE),
        re.compile(r'UNION\s+SELECT', re.IGNORECASE),
        re.compile(r'INSERT\s+INTO', re.IGNORECASE),
        re.compile(r'DELETE\s+FROM', re.IGNORECASE),
        re.compile(r'DROP\s+TABLE', re.IGNORECASE),
    ]
    
    # XSS patterns to detect
    XSS_PATTERNS = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'<iframe', re.IGNORECASE),
        re.compile(r'<object', re.IGNORECASE),
        re.compile(r'<embed', re.IGNORECASE),
    ]
    
    @classmethod
    def validate_email(cls, email):
        """Validate email format"""
        if not email or not isinstance(email, str):
            return False
        return bool(cls.EMAIL_PATTERN.match(email.strip()))
    
    @classmethod
    def validate_username(cls, username):
        """Validate username format"""
        if not username or not isinstance(username, str):
            return False
        return bool(cls.USERNAME_PATTERN.match(username))
    
    @classmethod
    def validate_password(cls, password):
        """
        Validate password strength
        Returns (bool, str) - (is_valid, error_message)
        """
        if not password or not isinstance(password, str):
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if len(password) > 128:
            return False, "Password must be less than 128 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, ""
    
    @classmethod
    def check_sql_injection(cls, text):
        """Check if text contains SQL injection patterns"""
        if not text:
            return False
        
        for pattern in cls.SQL_PATTERNS:
            if pattern.search(str(text)):
                logger.warning(f"Potential SQL injection detected: {text[:50]}...")
                return True
        return False
    
    @classmethod
    def check_xss(cls, text):
        """Check if text contains XSS patterns"""
        if not text:
            return False
        
        for pattern in cls.XSS_PATTERNS:
            if pattern.search(str(text)):
                logger.warning(f"Potential XSS detected: {text[:50]}...")
                return True
        return False
    
    @classmethod
    def sanitize_html(cls, text):
        """Escape HTML entities to prevent XSS"""
        if not text:
            return text
        return html.escape(str(text))
    
    @classmethod
    def sanitize_message(cls, message):
        """
        Sanitize a chat message
        Returns (sanitized_message, is_safe)
        """
        if not message or not isinstance(message, str):
            return "", False
        
        # Check for malicious patterns
        if cls.check_sql_injection(message) or cls.check_xss(message):
            return "", False
        
        # Limit length
        message = message[:2000]
        
        # Escape HTML
        sanitized = cls.sanitize_html(message)
        
        return sanitized, True


class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self._requests = {}
    
    def is_rate_limited(self, key, max_requests=10, window_seconds=60):
        """
        Check if a key is rate limited
        
        Args:
            key: Identifier (IP, user_id, etc.)
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
            
        Returns:
            bool: True if rate limited
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_seconds)
        
        # Clean old entries
        if key in self._requests:
            self._requests[key] = [
                ts for ts in self._requests[key] 
                if ts > window_start
            ]
        else:
            self._requests[key] = []
        
        # Check limit
        if len(self._requests[key]) >= max_requests:
            return True
        
        # Record this request
        self._requests[key].append(now)
        return False
    
    def get_remaining(self, key, max_requests=10, window_seconds=60):
        """Get remaining requests for a key"""
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_seconds)
        
        if key not in self._requests:
            return max_requests
        
        valid_requests = [
            ts for ts in self._requests[key] 
            if ts > window_start
        ]
        
        return max(0, max_requests - len(valid_requests))


# Global rate limiter instance
rate_limiter = RateLimiter()


def login_required(f):
    """Decorator to require authentication"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check session validity
        if 'session_expires' in session:
            session_expires = session['session_expires']
            # Handle both naive and aware datetimes
            now = datetime.now(timezone.utc)
            if hasattr(session_expires, 'tzinfo') and session_expires.tzinfo is None:
                session_expires = session_expires.replace(tzinfo=timezone.utc)
            if now > session_expires:
                session.clear()
                return jsonify({'error': 'Session expired'}), 401
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        if not session.get('is_admin', False):
            return jsonify({'error': 'Admin privileges required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


def rate_limit(max_requests=10, window_seconds=60):
    """Decorator for rate limiting"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Use IP as key
            key = request.remote_addr or 'unknown'
            
            if rate_limiter.is_rate_limited(key, max_requests, window_seconds):
                remaining = rate_limiter.get_remaining(key, max_requests, window_seconds)
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': window_seconds,
                    'remaining': remaining
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_input(f):
    """Decorator to validate request inputs for injection attacks"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Check JSON body
        if request.is_json:
            for key, value in request.json.items():
                if isinstance(value, str):
                    if InputValidator.check_sql_injection(value):
                        logger.warning(f"SQL injection attempt from {request.remote_addr}")
                        return jsonify({'error': 'Invalid input detected'}), 400
                    if InputValidator.check_xss(value):
                        logger.warning(f"XSS attempt from {request.remote_addr}")
                        return jsonify({'error': 'Invalid input detected'}), 400
        
        # Check form data
        for key, value in request.form.items():
            if InputValidator.check_sql_injection(value):
                logger.warning(f"SQL injection attempt from {request.remote_addr}")
                return jsonify({'error': 'Invalid input detected'}), 400
            if InputValidator.check_xss(value):
                logger.warning(f"XSS attempt from {request.remote_addr}")
                return jsonify({'error': 'Invalid input detected'}), 400
        
        # Check query parameters
        for key, value in request.args.items():
            if InputValidator.check_sql_injection(value):
                logger.warning(f"SQL injection attempt from {request.remote_addr}")
                return jsonify({'error': 'Invalid input detected'}), 400
        
        return f(*args, **kwargs)
    return decorated_function


def get_client_ip():
    """Get the real client IP address"""
    # Check for proxy headers
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers['X-Real-IP']
    return request.remote_addr


def log_security_event(event_type, description, user_id=None):
    """Log a security-related event"""
    from models import AuditLog, db
    
    try:
        AuditLog.log_event(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')[:256]
        )
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
