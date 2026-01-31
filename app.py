"""
Streamzy - Secure Terminal-Style Chat Platform
Main Flask Application with WebSocket support
"""
import os
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import local modules
from config import config
from models import db, bcrypt, User, Application, Message, Room, RoomMember, AuditLog, init_db
from encryption import encrypt_message, decrypt_message, get_encryption
from email_service import email_service
from security import (
    InputValidator, login_required, admin_required, rate_limit,
    validate_input, get_client_ip, log_security_event, rate_limiter
)

# Configure logging
log_handlers = [logging.StreamHandler()]
# Only add file handler if we can write to it
try:
    log_handlers.append(logging.FileHandler('streamzy.log'))
except (PermissionError, OSError):
    pass  # Skip file logging in production if no write access

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(config[os.environ.get('FLASK_ENV', 'development')])

# Initialize extensions
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)

# Initialize database
init_db(app)

# Initialize email service
email_service.init_app(app)

# Store connected users
connected_users = {}  # session_id -> user_info


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def check_activity_timeout(user):
    """Check if user has been inactive too long"""
    if not user.last_activity:
        return False
    
    timeout_minutes = app.config.get('ACTIVITY_TIMEOUT', 30)
    timeout_threshold = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)
    
    # Handle both naive and aware datetimes
    last_activity = user.last_activity
    if hasattr(last_activity, 'tzinfo') and last_activity.tzinfo is None:
        last_activity = last_activity.replace(tzinfo=timezone.utc)
    
    return last_activity < timeout_threshold


# =============================================================================
# WEB ROUTES
# =============================================================================

@app.route('/')
def index():
    """Landing page - redirect to login or chat"""
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))


@app.route('/apply', methods=['GET'])
def apply_page():
    """Application form page"""
    return render_template('apply.html')


@app.route('/login', methods=['GET'])
def login():
    """Login page"""
    return render_template('login.html')


@app.route('/chat')
@login_required
def chat():
    """Main chat interface"""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Check activity timeout
    if check_activity_timeout(user):
        session.clear()
        return redirect(url_for('login'))
    
    user.update_activity()
    db.session.commit()
    
    return render_template('chat.html', user=user)


@app.route('/admin')
@admin_required
def admin():
    """Admin dashboard"""
    return render_template('admin.html')


# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/api/apply', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300)
@validate_input
def api_apply():
    """Submit application for account"""
    data = request.get_json()
    
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    
    email = data['email'].strip().lower()
    
    # Validate email
    if not InputValidator.validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Check if email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 400
    
    # Check for pending application
    pending = Application.query.filter_by(email=email, status='pending').first()
    if pending:
        return jsonify({'error': 'Application already pending'}), 400
    
    # Create application
    application = Application(
        email=email,
        ip_address=get_client_ip(),
        status='pending'
    )
    
    db.session.add(application)
    db.session.commit()
    
    # Log event
    log_security_event('application_submitted', f'New application from {email}')
    
    # Send confirmation email
    email_service.send_application_received(email)
    
    logger.info(f"New application submitted: {email}")
    
    return jsonify({
        'success': True,
        'message': 'Application submitted successfully. Check your email for updates.'
    })


@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=300)
@validate_input
def api_login():
    """Authenticate user"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    # Find user
    user = User.query.filter_by(username=username).first()
    
    if not user:
        log_security_event('login_failed', f'Unknown username: {username}')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if account is locked
    if user.is_locked():
        log_security_event('login_locked', f'Locked account attempt: {username}', user.id)
        return jsonify({'error': 'Account temporarily locked. Try again later.'}), 403
    
    # Check if account is active
    if not user.is_active:
        log_security_event('login_inactive', f'Inactive account: {username}', user.id)
        return jsonify({'error': 'Account is not active'}), 403
    
    # Check if account is approved
    if not user.is_approved:
        return jsonify({'error': 'Account pending approval'}), 403
    
    # Verify password
    if not user.check_password(password):
        user.record_failed_login()
        db.session.commit()
        log_security_event('login_failed', f'Wrong password for: {username}', user.id)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Successful login
    user.reset_failed_attempts()
    user.last_login = datetime.now(timezone.utc)
    user.update_activity()
    session_token = user.generate_session_token()
    db.session.commit()
    
    # Set session
    session['user_id'] = user.id
    session['username'] = user.username
    session['is_admin'] = user.is_admin
    session['session_token'] = session_token
    session['session_expires'] = user.session_expires
    session.permanent = True
    
    log_security_event('login_success', f'Successful login: {username}', user.id)
    logger.info(f"User logged in: {username}")
    
    return jsonify({
        'success': True,
        'user': user.to_dict()
    })


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Logout user"""
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            user.invalidate_session()
            db.session.commit()
            log_security_event('logout', f'User logged out: {user.username}', user.id)
    
    session.clear()
    return jsonify({'success': True})


@app.route('/api/messages', methods=['GET'])
@login_required
def api_get_messages():
    """Get recent messages for a room - must be a member"""
    room_name = request.args.get('room')
    limit = min(int(request.args.get('limit', 50)), 100)
    user_id = session['user_id']
    
    if not room_name:
        return jsonify({'error': 'Room name required'}), 400
    
    # Check room exists and user is a member
    room = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    if not room.is_member(user_id):
        return jsonify({'error': 'You are not a member of this room'}), 403
    
    messages = Message.query.filter_by(room=room_name, is_deleted=False)\
        .order_by(Message.created_at.desc())\
        .limit(limit)\
        .all()
    
    # Decrypt and format messages
    result = []
    for msg in reversed(messages):
        try:
            content = decrypt_message(msg.encrypted_content)
            result.append({
                'id': msg.id,
                'username': msg.author.username if msg.author else 'Unknown',
                'content': content,
                'message_type': msg.message_type,
                'created_at': msg.created_at.isoformat()
            })
        except Exception as e:
            logger.error(f"Error decrypting message {msg.id}: {e}")
    
    return jsonify({'messages': result})


@app.route('/api/rooms', methods=['GET'])
@login_required
def api_get_rooms():
    """Get rooms the user is a member of"""
    user_id = session['user_id']
    
    # Get rooms user is a member of
    memberships = RoomMember.query.filter_by(user_id=user_id).all()
    room_ids = [m.room_id for m in memberships]
    
    rooms = Room.query.filter(Room.id.in_(room_ids), Room.is_active == True).all()
    
    return jsonify({
        'rooms': [room.to_dict() for room in rooms]
    })


@app.route('/api/rooms/join', methods=['POST'])
@login_required
@validate_input
def api_join_room():
    """Join a room with password"""
    data = request.get_json()
    
    if not data or 'room_name' not in data or 'password' not in data:
        return jsonify({'error': 'Room name and password required'}), 400
    
    room_name = data['room_name'].strip()
    password = data['password']
    user_id = session['user_id']
    
    # Find room
    room = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    # Check if already a member
    if room.is_member(user_id):
        return jsonify({'error': 'Already a member of this room'}), 400
    
    # Check password
    if not room.check_password(password):
        log_security_event('room_join_failed', f'Wrong password for room {room_name}', user_id)
        return jsonify({'error': 'Invalid room password'}), 401
    
    # Check max members
    if room.get_member_count() >= room.max_members:
        return jsonify({'error': 'Room is full'}), 400
    
    # Add member
    room.add_member(user_id)
    db.session.commit()
    
    log_security_event('room_joined', f'User joined room {room_name}', user_id)
    
    return jsonify({
        'success': True,
        'room': room.to_dict()
    })


@app.route('/api/rooms/leave', methods=['POST'])
@login_required
def api_leave_room():
    """Leave a room"""
    data = request.get_json()
    
    if not data or 'room_id' not in data:
        return jsonify({'error': 'Room ID required'}), 400
    
    room_id = data['room_id']
    user_id = session['user_id']
    
    room = db.session.get(Room, room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    if room.remove_member(user_id):
        db.session.commit()
        log_security_event('room_left', f'User left room {room.name}', user_id)
        return jsonify({'success': True})
    
    return jsonify({'error': 'Not a member of this room'}), 400


@app.route('/api/users/online', methods=['GET'])
@login_required
def api_online_users():
    """Get list of online users"""
    users = []
    for sid, info in connected_users.items():
        users.append({
            'username': info['username'],
            'room': info.get('room', 'general')
        })
    return jsonify({'users': users})


@app.route('/api/user/password', methods=['PUT'])
@login_required
@validate_input
def api_change_password():
    """Change user password"""
    data = request.get_json()
    
    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({'error': 'Current and new password required'}), 400
    
    user = db.session.get(User, session['user_id'])
    
    if not user.check_password(data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Validate new password
    is_valid, error_msg = InputValidator.validate_password(data['new_password'])
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    user.set_password(data['new_password'])
    db.session.commit()
    
    log_security_event('password_changed', f'Password changed for: {user.username}', user.id)
    
    return jsonify({'success': True, 'message': 'Password changed successfully'})


# =============================================================================
# ADMIN API ROUTES
# =============================================================================

@app.route('/api/admin/applications', methods=['GET'])
@admin_required
def api_admin_applications():
    """Get pending applications"""
    status = request.args.get('status', 'pending')
    applications = Application.query.filter_by(status=status)\
        .order_by(Application.created_at.desc())\
        .all()
    return jsonify({
        'applications': [app.to_dict() for app in applications]
    })


@app.route('/api/admin/applications/<int:app_id>/approve', methods=['POST'])
@admin_required
def api_admin_approve(app_id):
    """Approve an application"""
    application = db.session.get(Application, app_id)
    if not application:
        abort(404)
    
    if application.status != 'pending':
        return jsonify({'error': 'Application already processed'}), 400
    
    # Generate credentials
    username = User.generate_username()
    # Ensure unique username
    while User.query.filter_by(username=username).first():
        username = User.generate_username()
    
    password = User.generate_password()
    
    # Create user
    user = User(
        username=username,
        email=application.email,
        is_approved=True,
        is_active=True
    )
    user.set_password(password)
    
    # Update application
    application.status = 'approved'
    application.processed_at = datetime.now(timezone.utc)
    application.user_id = user.id
    
    db.session.add(user)
    db.session.commit()
    
    # Send credentials email
    email_service.send_credentials(application.email, username, password)
    
    log_security_event(
        'application_approved',
        f'Application approved for {application.email}, username: {username}',
        session['user_id']
    )
    
    logger.info(f"Application approved: {application.email} -> {username}")
    
    return jsonify({
        'success': True,
        'user': user.to_dict()
    })


@app.route('/api/admin/applications/<int:app_id>/reject', methods=['POST'])
@admin_required
def api_admin_reject(app_id):
    """Reject an application"""
    application = db.session.get(Application, app_id)
    if not application:
        abort(404)
    data = request.get_json() or {}
    
    if application.status != 'pending':
        return jsonify({'error': 'Application already processed'}), 400
    
    application.status = 'rejected'
    application.processed_at = datetime.now(timezone.utc)
    application.admin_notes = data.get('reason', '')
    
    db.session.commit()
    
    log_security_event(
        'application_rejected',
        f'Application rejected for {application.email}',
        session['user_id']
    )
    
    return jsonify({'success': True})


@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    """Get all users"""
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({
        'users': [user.to_dict() for user in users]
    })


# =============================================================================
# ADMIN ROOM MANAGEMENT
# =============================================================================

@app.route('/api/admin/rooms', methods=['GET'])
@admin_required
def api_admin_rooms():
    """Get all rooms"""
    rooms = Room.query.order_by(Room.created_at.desc()).all()
    return jsonify({
        'rooms': [room.to_dict(include_members=True) for room in rooms]
    })


@app.route('/api/admin/rooms', methods=['POST'])
@admin_required
@validate_input
def api_admin_create_room():
    """Create a new room with password"""
    data = request.get_json()
    
    if not data or 'name' not in data or 'password' not in data:
        return jsonify({'error': 'Room name and password required'}), 400
    
    name = data['name'].strip().lower().replace(' ', '_')
    password = data['password']
    description = data.get('description', '')
    max_members = data.get('max_members', 50)
    
    # Validate room name
    if len(name) < 3 or len(name) > 50:
        return jsonify({'error': 'Room name must be 3-50 characters'}), 400
    
    if not name.replace('_', '').isalnum():
        return jsonify({'error': 'Room name can only contain letters, numbers, and underscores'}), 400
    
    # Check if room exists
    if Room.query.filter_by(name=name).first():
        return jsonify({'error': 'Room name already exists'}), 400
    
    # Validate password
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Create room
    room = Room(
        name=name,
        description=description,
        is_private=True,
        max_members=max_members,
        created_by=session['user_id']
    )
    room.set_password(password)
    
    db.session.add(room)
    db.session.commit()
    
    log_security_event('room_created', f'Room created: {name}', session['user_id'])
    logger.info(f"Room created: {name} by admin")
    
    return jsonify({
        'success': True,
        'room': room.to_dict(),
        'password': password  # Return password so admin can share it
    })


@app.route('/api/admin/rooms/<int:room_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_room(room_id):
    """Delete a room"""
    room = db.session.get(Room, room_id)
    if not room:
        abort(404)
    
    room_name = room.name
    db.session.delete(room)
    db.session.commit()
    
    log_security_event('room_deleted', f'Room deleted: {room_name}', session['user_id'])
    
    return jsonify({'success': True})


@app.route('/api/admin/rooms/<int:room_id>/password', methods=['PUT'])
@admin_required
@validate_input
def api_admin_reset_room_password(room_id):
    """Reset room password"""
    room = db.session.get(Room, room_id)
    if not room:
        abort(404)
    
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'error': 'New password required'}), 400
    
    password = data['password']
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    room.set_password(password)
    db.session.commit()
    
    log_security_event('room_password_reset', f'Password reset for room: {room.name}', session['user_id'])
    
    return jsonify({
        'success': True,
        'password': password
    })


@app.route('/api/admin/rooms/<int:room_id>/members', methods=['GET'])
@admin_required
def api_admin_room_members(room_id):
    """Get room members"""
    room = db.session.get(Room, room_id)
    if not room:
        abort(404)
    
    members = []
    for m in room.members.all():
        if m.user:
            members.append({
                'id': m.user.id,
                'username': m.user.username,
                'joined_at': m.joined_at.isoformat() if m.joined_at else None
            })
    
    return jsonify({'members': members})


@app.route('/api/admin/rooms/<int:room_id>/members/<int:user_id>', methods=['DELETE'])
@admin_required
def api_admin_remove_member(room_id, user_id):
    """Remove a user from a room"""
    room = db.session.get(Room, room_id)
    if not room:
        abort(404)
    
    if room.remove_member(user_id):
        db.session.commit()
        log_security_event('member_removed', f'User {user_id} removed from room {room.name}', session['user_id'])
        return jsonify({'success': True})
    
    return jsonify({'error': 'User is not a member'}), 400


@app.route('/api/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def api_admin_toggle_user(user_id):
    """Toggle user active status"""
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    
    if user.id == session['user_id']:
        return jsonify({'error': 'Cannot modify your own account'}), 400
    
    user.is_active = not user.is_active
    db.session.commit()
    
    action = 'activated' if user.is_active else 'deactivated'
    log_security_event(
        f'user_{action}',
        f'User {user.username} {action}',
        session['user_id']
    )
    
    return jsonify({'success': True, 'is_active': user.is_active})


@app.route('/api/admin/audit-logs', methods=['GET'])
@admin_required
def api_admin_audit_logs():
    """Get recent audit logs"""
    limit = min(int(request.args.get('limit', 100)), 500)
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    
    return jsonify({
        'logs': [{
            'id': log.id,
            'event_type': log.event_type,
            'description': log.event_description,
            'ip_address': log.ip_address,
            'created_at': log.created_at.isoformat()
        } for log in logs]
    })


# =============================================================================
# WEBSOCKET EVENTS
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    if 'user_id' not in session:
        disconnect()
        return False
    
    user = db.session.get(User, session['user_id'])
    if not user or not user.is_active:
        disconnect()
        return False
    
    # Store connection info (no default room)
    connected_users[request.sid] = {
        'user_id': user.id,
        'username': user.username,
        'room': None
    }
    
    user.update_activity()
    db.session.commit()
    
    # Send list of user's rooms
    memberships = RoomMember.query.filter_by(user_id=user.id).all()
    room_ids = [m.room_id for m in memberships]
    rooms = Room.query.filter(Room.id.in_(room_ids), Room.is_active == True).all()
    
    emit('connected', {
        'username': user.username,
        'rooms': [r.to_dict() for r in rooms]
    })
    
    logger.info(f"User connected: {user.username}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if request.sid in connected_users:
        user_info = connected_users.pop(request.sid)
        
        if user_info.get('room'):
            emit('user_left', {
                'username': user_info['username'],
                'users': list(set(u['username'] for u in connected_users.values() if u.get('room') == user_info['room']))
            }, room=user_info['room'])
        
        logger.info(f"User disconnected: {user_info['username']}")


@socketio.on('join_room')
def handle_join_room(data):
    """Handle user joining a room - must be a member"""
    if 'user_id' not in session:
        return
    
    room_name = data.get('room')
    if not room_name:
        emit('error', {'message': 'Room name required'})
        return
    
    user_id = session['user_id']
    
    # Check room exists and user is a member
    room = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room:
        emit('error', {'message': 'Room not found'})
        return
    
    if not room.is_member(user_id):
        emit('error', {'message': 'You are not a member of this room'})
        return
    
    old_room = connected_users.get(request.sid, {}).get('room')
    
    if old_room:
        leave_room(old_room)
        emit('user_left', {
            'username': session['username']
        }, room=old_room)
    
    join_room(room_name)
    
    if request.sid in connected_users:
        connected_users[request.sid]['room'] = room_name
    
    # Get users in this room
    users_in_room = [u['username'] for u in connected_users.values() if u.get('room') == room_name]
    
    emit('room_joined', {
        'room': room_name,
        'room_info': room.to_dict(),
        'users': users_in_room
    })
    
    emit('user_joined', {
        'username': session['username'],
        'users': users_in_room
    }, room=room_name, include_self=False)


@socketio.on('message')
def handle_message(data):
    """Handle incoming chat message"""
    if 'user_id' not in session:
        return
    
    user = db.session.get(User, session['user_id'])
    if not user or not user.is_active:
        disconnect()
        return
    
    content = data.get('content', '').strip()
    room_name = data.get('room')
    
    # Must have a room
    if not room_name:
        emit('error', {'message': 'No room selected'})
        return
    
    # Check user is member of room
    room = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room or not room.is_member(user.id):
        emit('error', {'message': 'You are not a member of this room'})
        return
    
    # Validate message
    if not content:
        emit('error', {'message': 'Empty message'})
        return
    
    # Sanitize
    sanitized, is_safe = InputValidator.sanitize_message(content)
    if not is_safe:
        emit('error', {'message': 'Message contains invalid content'})
        log_security_event('message_blocked', f'Blocked message from {user.username}', user.id)
        return
    
    # Rate limit messages
    if rate_limiter.is_rate_limited(f"msg_{user.id}", max_requests=30, window_seconds=60):
        emit('error', {'message': 'Rate limit exceeded. Slow down!'})
        return
    
    # Encrypt and save message
    encrypted_content = encrypt_message(sanitized)
    
    message = Message(
        user_id=user.id,
        encrypted_content=encrypted_content,
        room=room_name,
        message_type='text'
    )
    
    db.session.add(message)
    user.update_activity()
    db.session.commit()
    
    # Broadcast to room
    emit('new_message', {
        'id': message.id,
        'username': user.username,
        'content': sanitized,
        'message_type': 'text',
        'created_at': message.created_at.isoformat()
    }, room=room_name)


@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator"""
    if 'user_id' not in session:
        return
    
    room_name = data.get('room')
    if not room_name:
        return
    
    emit('user_typing', {
        'username': session['username'],
        'is_typing': data.get('is_typing', True)
    }, room=room_name, include_self=False)


@socketio.on('command')
def handle_command(data):
    """Handle terminal commands"""
    if 'user_id' not in session:
        return
    
    command = data.get('command', '').strip()
    room = data.get('room', 'general')
    
    if not command:
        return
    
    # Process commands
    response = None
    
    if command == '/help':
        response = """Available commands:
/help - Show this help
/users - List online users
/rooms - List available rooms
/join <room> - Join a room
/clear - Clear terminal
/whoami - Show your username
/time - Show server time"""
    
    elif command == '/users':
        users = list(set(u['username'] for u in connected_users.values()))
        response = f"Online users ({len(users)}): " + ", ".join(users)
    
    elif command == '/rooms':
        rooms = Room.query.filter_by(is_active=True).all()
        response = "Available rooms: " + ", ".join(r.name for r in rooms)
    
    elif command.startswith('/join '):
        room_name = command[6:].strip()
        room = Room.query.filter_by(name=room_name, is_active=True).first()
        if room:
            handle_join_room({'room': room_name})
            response = f"Joined room: {room_name}"
        else:
            response = f"Room not found: {room_name}"
    
    elif command == '/whoami':
        response = f"You are: {session['username']}"
    
    elif command == '/time':
        response = f"Server time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    
    elif command == '/clear':
        emit('clear_terminal')
        return
    
    else:
        response = f"Unknown command: {command}. Type /help for available commands."
    
    if response:
        emit('command_response', {
            'command': command,
            'response': response
        })


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500


@app.errorhandler(429)
def rate_limit_error(e):
    return jsonify({'error': 'Too many requests. Please slow down.'}), 429


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    
    logger.info(f"Starting Streamzy on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
