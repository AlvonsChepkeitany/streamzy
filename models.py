"""
Database models for Streamzy Chat Platform
"""
from datetime import datetime, timedelta, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import secrets
import string

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model):
    """User model for authentication and profile"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime)
    
    # Session management
    session_token = db.Column(db.String(128), unique=True)
    session_expires = db.Column(db.DateTime)
    
    # Failed login attempts (for rate limiting)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Relationships
    messages = db.relationship('Message', backref='author', lazy='dynamic',
                               foreign_keys='Message.user_id')
    applications = db.relationship('Application', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Hash and set the password"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def generate_session_token(self, hours=2):
        """Generate a new session token"""
        self.session_token = secrets.token_urlsafe(64)
        self.session_expires = datetime.now(timezone.utc) + timedelta(hours=hours)
        return self.session_token
    
    def is_session_valid(self):
        """Check if current session is valid"""
        if not self.session_token or not self.session_expires:
            return False
        return datetime.now(timezone.utc) < self.session_expires
    
    def invalidate_session(self):
        """Invalidate current session"""
        self.session_token = None
        self.session_expires = None
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now(timezone.utc)
    
    def is_locked(self):
        """Check if account is locked due to failed attempts"""
        if self.locked_until and datetime.now(timezone.utc) < self.locked_until:
            return True
        return False
    
    def record_failed_login(self):
        """Record a failed login attempt"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    def reset_failed_attempts(self):
        """Reset failed login counter"""
        self.failed_login_attempts = 0
        self.locked_until = None
    
    @staticmethod
    def generate_username():
        """Generate a unique hacker-style username"""
        prefixes = ['cyber', 'ghost', 'shadow', 'neo', 'zero', 'cipher', 'phantom', 
                   'nexus', 'vector', 'proxy', 'delta', 'omega', 'echo', 'pulse',
                   'quantum', 'binary', 'hex', 'null', 'void', 'apex']
        suffixes = ['runner', 'walker', 'hunter', 'seeker', 'blade', 'storm',
                   'wave', 'byte', 'bit', 'node', 'core', 'flux', 'spark', 'volt']
        
        prefix = secrets.choice(prefixes)
        suffix = secrets.choice(suffixes)
        number = secrets.randbelow(1000)
        
        return f"{prefix}_{suffix}_{number:03d}"
    
    @staticmethod
    def generate_password(length=16):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        # Ensure at least one of each type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*")
        ]
        # Fill the rest
        password += [secrets.choice(alphabet) for _ in range(length - 4)]
        # Shuffle
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    def to_dict(self):
        """Convert user to dictionary (safe fields only)"""
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class Application(db.Model):
    """Registration application model"""
    __tablename__ = 'applications'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    
    # Application status
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    
    # Reference to created user (if approved)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Admin notes
    admin_notes = db.Column(db.Text)
    
    # IP address for security
    ip_address = db.Column(db.String(45))
    
    def to_dict(self):
        """Convert application to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None
        }
    
    def __repr__(self):
        return f'<Application {self.email}>'


class Message(db.Model):
    """Chat message model with encryption support"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Encrypted message content
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    
    # Message metadata
    room = db.Column(db.String(50), default='general', index=True)
    message_type = db.Column(db.String(20), default='text')  # text, system, command
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Edit tracking
    edited_at = db.Column(db.DateTime)
    is_deleted = db.Column(db.Boolean, default=False)
    
    def to_dict(self, include_content=False):
        """Convert message to dictionary"""
        result = {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.author.username if self.author else 'Unknown',
            'room': self.room,
            'message_type': self.message_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_deleted': self.is_deleted
        }
        if include_content and not self.is_deleted:
            # Content will be decrypted by the caller
            result['encrypted_content'] = self.encrypted_content
        return result
    
    def __repr__(self):
        return f'<Message {self.id}>'


class Room(db.Model):
    """Chat room model with password protection"""
    __tablename__ = 'rooms'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    
    # Password protection (hashed)
    password_hash = db.Column(db.String(128))
    
    # Room settings
    is_private = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    max_members = db.Column(db.Integer, default=50)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Creator (admin only)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    creator = db.relationship('User', backref='created_rooms', foreign_keys=[created_by])
    
    # Members relationship
    members = db.relationship('RoomMember', backref='room', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set room password"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        if not self.password_hash:
            return True  # No password set
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def is_member(self, user_id):
        """Check if user is a member of this room"""
        return RoomMember.query.filter_by(room_id=self.id, user_id=user_id).first() is not None
    
    def add_member(self, user_id):
        """Add a user to the room"""
        if not self.is_member(user_id):
            member = RoomMember(room_id=self.id, user_id=user_id)
            db.session.add(member)
            return True
        return False
    
    def remove_member(self, user_id):
        """Remove a user from the room"""
        member = RoomMember.query.filter_by(room_id=self.id, user_id=user_id).first()
        if member:
            db.session.delete(member)
            return True
        return False
    
    def get_member_count(self):
        """Get number of members in the room"""
        return self.members.count()
    
    def to_dict(self, include_members=False):
        """Convert room to dictionary"""
        result = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_private': self.is_private,
            'has_password': self.password_hash is not None,
            'max_members': self.max_members,
            'member_count': self.get_member_count(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.creator.username if self.creator else None
        }
        if include_members:
            result['members'] = [m.user.username for m in self.members.all() if m.user]
        return result
    
    def __repr__(self):
        return f'<Room {self.name}>'


class RoomMember(db.Model):
    """Room membership model"""
    __tablename__ = 'room_members'
    
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('room_id', 'user_id', name='unique_room_member'),)
    
    user = db.relationship('User', backref='room_memberships')
    
    def __repr__(self):
        return f'<RoomMember room={self.room_id} user={self.user_id}>'


class AuditLog(db.Model):
    """Security audit log"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Event details
    event_type = db.Column(db.String(50), nullable=False, index=True)
    event_description = db.Column(db.Text)
    
    # Request metadata
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(256))
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    @staticmethod
    def log_event(event_type, description, user_id=None, ip_address=None, user_agent=None):
        """Create a new audit log entry"""
        log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_description=description,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def __repr__(self):
        return f'<AuditLog {self.event_type}>'


def init_db(app):
    """Initialize database with app context"""
    db.init_app(app)
    bcrypt.init_app(app)
    
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@streamzy.local',
                is_admin=True,
                is_approved=True,
                is_active=True
            )
            admin.set_password('changeme123!')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
        
        # No default room - admin must create groups with passwords
        
        db.session.commit()
