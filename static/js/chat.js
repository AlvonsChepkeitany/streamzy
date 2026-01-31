/**
 * Streamzy Chat Client
 * WebSocket-based real-time chat with password-protected rooms
 */

class StreamzyChat {
    constructor() {
        this.socket = null;
        this.currentRoom = null;
        this.rooms = [];
        this.commandHistory = [];
        this.historyIndex = -1;
        this.typingTimeout = null;
        this.isTyping = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        
        // DOM Elements
        this.output = document.getElementById('terminalOutput');
        this.input = document.getElementById('messageInput');
        this.userList = document.getElementById('userList');
        this.userCount = document.getElementById('userCount');
        this.roomList = document.getElementById('roomList');
        this.typingIndicator = document.getElementById('typingIndicator');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.charCount = document.getElementById('charCount');
        
        // Initialize
        this.init();
    }
    
    init() {
        this.setupSocket();
        this.setupEventListeners();
    }
    
    setupSocket() {
        // Connect to WebSocket
        this.socket = io({
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: this.maxReconnectAttempts
        });
        
        // Connection events
        this.socket.on('connect', () => this.onConnect());
        this.socket.on('connected', (data) => this.onConnected(data));
        this.socket.on('disconnect', () => this.onDisconnect());
        this.socket.on('connect_error', (error) => this.onConnectError(error));
        
        // Chat events
        this.socket.on('new_message', (data) => this.onNewMessage(data));
        this.socket.on('user_joined', (data) => this.onUserJoined(data));
        this.socket.on('user_left', (data) => this.onUserLeft(data));
        this.socket.on('user_typing', (data) => this.onUserTyping(data));
        this.socket.on('room_joined', (data) => this.onRoomJoined(data));
        this.socket.on('command_response', (data) => this.onCommandResponse(data));
        this.socket.on('clear_terminal', () => this.clearTerminal());
        this.socket.on('error', (data) => this.onError(data));
    }
    
    setupEventListeners() {
        // Input handling
        this.input.addEventListener('keydown', (e) => this.handleKeyDown(e));
        this.input.addEventListener('input', (e) => this.handleInput(e));
        
        // Character count
        this.input.addEventListener('input', () => {
            this.charCount.textContent = this.input.value.length;
        });
        
        // Sidebar toggle
        const toggleBtn = document.getElementById('toggleSidebar');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleSidebar());
        }
        
        // Clear terminal
        const clearBtn = document.getElementById('clearTerminal');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearTerminal());
        }
        
        // Logout
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.logout());
        }
        
        // Join room button
        const joinRoomBtn = document.getElementById('joinRoomBtn');
        if (joinRoomBtn) {
            joinRoomBtn.addEventListener('click', () => this.showJoinModal());
        }
        
        // Focus input on click
        document.addEventListener('click', (e) => {
            if (!e.target.closest('button') && !e.target.closest('a') && !e.target.closest('.sidebar') && !e.target.closest('.modal')) {
                this.input.focus();
            }
        });
        
        // Initial focus
        this.input.focus();
    }
    
    // ========================================
    // Socket Event Handlers
    // ========================================
    
    onConnect() {
        this.updateConnectionStatus('connecting', 'Connecting...');
    }
    
    onConnected(data) {
        this.updateConnectionStatus('connected', 'Connected');
        this.reconnectAttempts = 0;
        this.addSystemMessage('Connected to server');
        
        // Update rooms list
        this.rooms = data.rooms || [];
        this.updateRoomList();
        
        // Auto-join first room if available
        if (this.rooms.length > 0) {
            this.joinRoom(this.rooms[0].name);
        } else {
            this.addSystemMessage('You are not a member of any rooms. Use /join <room> <password> or click [+] to join a room.');
        }
    }
    
    onDisconnect() {
        this.updateConnectionStatus('disconnected', 'Disconnected');
        this.addSystemMessage('Disconnected from server', 'error');
    }
    
    onConnectError(error) {
        this.reconnectAttempts++;
        this.updateConnectionStatus('connecting', `Reconnecting (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            this.addSystemMessage('Connection failed. Please refresh the page.', 'error');
        }
    }
    
    onNewMessage(data) {
        const isSelf = data.username === window.currentUser.username;
        
        const line = Terminal.createMessageLine({
            username: data.username,
            content: data.content,
            timestamp: data.created_at,
            isSelf: isSelf
        });
        
        this.output.appendChild(line);
        this.scrollToBottom();
        
        // Notification for others' messages
        if (!isSelf && document.hidden) {
            Terminal.playNotification();
        }
    }
    
    onUserJoined(data) {
        this.addSystemMessage(`${data.username} joined the room`);
        if (data.users) {
            this.updateUserList(data.users);
        }
    }
    
    onUserLeft(data) {
        this.addSystemMessage(`${data.username} left the room`);
        if (data.users) {
            this.updateUserList(data.users);
        }
    }
    
    onUserTyping(data) {
        if (data.is_typing) {
            this.typingIndicator.querySelector('.typing-user').textContent = data.username;
            this.typingIndicator.classList.remove('hidden');
        } else {
            this.typingIndicator.classList.add('hidden');
        }
    }
    
    onRoomJoined(data) {
        this.currentRoom = data.room;
        document.getElementById('currentRoom').textContent = data.room;
        document.getElementById('inputRoom').textContent = data.room;
        document.getElementById('terminalTitle').textContent = `STREAMZY_TERMINAL :: ${window.currentUser.username}@${data.room}`;
        
        // Enable input
        this.input.disabled = false;
        this.input.placeholder = 'Enter message or /help for commands';
        
        this.addSystemMessage(`Joined room: ${data.room}`);
        
        // Update user list
        if (data.users) {
            this.updateUserList(data.users);
        }
        
        // Update room list highlight
        this.updateRoomListHighlight();
        
        // Load message history for this room
        this.loadMessageHistory();
    }
    
    onCommandResponse(data) {
        const response = Terminal.createCommandResponse(data.response);
        this.output.appendChild(response);
        this.scrollToBottom();
    }
    
    onError(data) {
        this.addSystemMessage(data.message, 'error');
    }
    
    // ========================================
    // Room Management
    // ========================================
    
    joinRoom(roomName) {
        this.socket.emit('join_room', { room: roomName });
    }
    
    showJoinModal() {
        document.getElementById('joinRoomModal').classList.remove('hidden');
        document.getElementById('joinRoomName').focus();
    }
    
    updateRoomList() {
        if (this.rooms.length === 0) {
            this.roomList.innerHTML = '<div class="no-rooms">No rooms joined yet</div>';
            return;
        }
        
        this.roomList.innerHTML = this.rooms.map(room => `
            <div class="room-item ${room.name === this.currentRoom ? 'active' : ''}" data-room="${room.name}" onclick="chat.joinRoom('${room.name}')">
                <span class="room-icon">📁</span>
                <span class="room-name">${Terminal.escapeHtml(room.name)}</span>
            </div>
        `).join('');
    }
    
    updateRoomListHighlight() {
        document.querySelectorAll('.room-item').forEach(el => {
            el.classList.toggle('active', el.dataset.room === this.currentRoom);
        });
    }
    
    // ========================================
    // Input Handling
    // ========================================
    
    handleKeyDown(e) {
        switch (e.key) {
            case 'Enter':
                e.preventDefault();
                this.sendMessage();
                break;
                
            case 'ArrowUp':
                e.preventDefault();
                this.navigateHistory(-1);
                break;
                
            case 'ArrowDown':
                e.preventDefault();
                this.navigateHistory(1);
                break;
                
            case 'Tab':
                e.preventDefault();
                this.autocomplete();
                break;
                
            case 'Escape':
                this.input.value = '';
                this.charCount.textContent = '0';
                break;
        }
    }
    
    handleInput(e) {
        if (!this.currentRoom) return;
        
        // Send typing indicator
        if (!this.isTyping) {
            this.isTyping = true;
            this.socket.emit('typing', { room: this.currentRoom, is_typing: true });
        }
        
        // Clear previous timeout
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        
        // Set timeout to stop typing indicator
        this.typingTimeout = setTimeout(() => {
            this.isTyping = false;
            this.socket.emit('typing', { room: this.currentRoom, is_typing: false });
        }, 2000);
    }
    
    sendMessage() {
        const content = this.input.value.trim();
        
        if (!content) return;
        
        // Handle /join command specially
        if (content.startsWith('/join ')) {
            const parts = content.substring(6).split(' ');
            if (parts.length >= 2) {
                this.apiJoinRoom(parts[0], parts.slice(1).join(' '));
                this.input.value = '';
                this.charCount.textContent = '0';
                return;
            } else {
                this.addSystemMessage('Usage: /join <room_name> <password>', 'error');
                return;
            }
        }
        
        // Require room for non-join commands
        if (!this.currentRoom && !content.startsWith('/join')) {
            this.addSystemMessage('You must join a room first. Use /join <room> <password>', 'error');
            return;
        }
        
        // Add to history
        this.commandHistory.push(content);
        this.historyIndex = this.commandHistory.length;
        
        // Check if it's a command
        if (content.startsWith('/')) {
            this.socket.emit('command', {
                command: content,
                room: this.currentRoom
            });
        } else {
            this.socket.emit('message', {
                content: content,
                room: this.currentRoom
            });
        }
        
        // Clear input
        this.input.value = '';
        this.charCount.textContent = '0';
        
        // Stop typing indicator
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        this.isTyping = false;
        if (this.currentRoom) {
            this.socket.emit('typing', { room: this.currentRoom, is_typing: false });
        }
    }
    
    async apiJoinRoom(roomName, password) {
        try {
            const response = await fetch('/api/rooms/join', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': window.CSRF_TOKEN
                },
                body: JSON.stringify({
                    room_name: roomName,
                    password: password
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.addSystemMessage(`Successfully joined room: ${roomName}`);
                this.rooms.push(data.room);
                this.updateRoomList();
                this.joinRoom(roomName);
            } else {
                this.addSystemMessage(data.error || 'Failed to join room', 'error');
            }
        } catch (error) {
            console.error('Failed to join room:', error);
            this.addSystemMessage('Failed to join room', 'error');
        }
    }
    
    navigateHistory(direction) {
        if (this.commandHistory.length === 0) return;
        
        this.historyIndex += direction;
        
        if (this.historyIndex < 0) {
            this.historyIndex = 0;
        } else if (this.historyIndex >= this.commandHistory.length) {
            this.historyIndex = this.commandHistory.length;
            this.input.value = '';
            return;
        }
        
        this.input.value = this.commandHistory[this.historyIndex];
        this.charCount.textContent = this.input.value.length;
        
        // Move cursor to end
        setTimeout(() => {
            this.input.selectionStart = this.input.selectionEnd = this.input.value.length;
        }, 0);
    }
    
    autocomplete() {
        const value = this.input.value;
        
        // Command autocomplete
        if (value.startsWith('/')) {
            const commands = ['/help', '/users', '/rooms', '/join ', '/leave', '/clear', '/whoami', '/time'];
            const matches = commands.filter(cmd => cmd.startsWith(value));
            
            if (matches.length === 1) {
                this.input.value = matches[0];
                this.charCount.textContent = this.input.value.length;
            } else if (matches.length > 1) {
                this.addSystemMessage('Commands: ' + matches.join(', '));
            }
        }
    }
    
    // ========================================
    // UI Updates
    // ========================================
    
    addSystemMessage(content, type = 'system') {
        const line = Terminal.createSystemLine(content, type);
        this.output.appendChild(line);
        this.scrollToBottom();
    }
    
    updateConnectionStatus(status, text) {
        const dot = this.connectionStatus.querySelector('.status-dot');
        const statusText = this.connectionStatus.querySelector('.status-text');
        
        dot.className = 'status-dot ' + status;
        statusText.textContent = text;
    }
    
    updateUserList(users) {
        this.userCount.textContent = users.length;
        
        this.userList.innerHTML = users.map(username => `
            <div class="user-item">
                <span class="user-status"></span>
                <span class="user-name ${username === window.currentUser.username ? 'current' : ''}">${Terminal.escapeHtml(username)}</span>
            </div>
        `).join('');
    }
    
    scrollToBottom() {
        Terminal.scrollToBottom(this.output);
    }
    
    clearTerminal() {
        // Keep the welcome header
        const welcomeElements = this.output.querySelectorAll('.output-line');
        const toRemove = [];
        
        welcomeElements.forEach((el, index) => {
            if (index > 4) { // Keep first 5 lines (welcome message)
                toRemove.push(el);
            }
        });
        
        // Also remove all message lines
        this.output.querySelectorAll('.message-line, .command-response').forEach(el => {
            toRemove.push(el);
        });
        
        toRemove.forEach(el => el.remove());
        
        this.addSystemMessage('Terminal cleared');
    }
    
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.toggle('open');
    }
    
    // ========================================
    // Data Loading
    // ========================================
    
    async loadMessageHistory() {
        if (!this.currentRoom) return;
        
        try {
            const response = await fetch(`/api/messages?room=${this.currentRoom}&limit=50`);
            const data = await response.json();
            
            if (data.messages && data.messages.length > 0) {
                data.messages.forEach(msg => {
                    const isSelf = msg.username === window.currentUser.username;
                    const line = Terminal.createMessageLine({
                        username: msg.username,
                        content: msg.content,
                        timestamp: msg.created_at,
                        type: msg.message_type,
                        isSelf: isSelf
                    });
                    this.output.appendChild(line);
                });
                
                this.scrollToBottom();
            }
        } catch (error) {
            console.error('Failed to load message history:', error);
        }
    }
    
    // ========================================
    // Logout
    // ========================================
    
    async logout() {
        try {
            await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': window.CSRF_TOKEN
                }
            });
        } catch (error) {
            console.error('Logout error:', error);
        }
        
        window.location.href = '/login';
    }
}

// Global functions for modal
function closeJoinModal() {
    document.getElementById('joinRoomModal').classList.add('hidden');
    document.getElementById('joinRoomName').value = '';
    document.getElementById('joinRoomPassword').value = '';
    document.getElementById('joinError').classList.add('hidden');
}

async function submitJoinRoom() {
    const roomName = document.getElementById('joinRoomName').value.trim();
    const password = document.getElementById('joinRoomPassword').value;
    const errorEl = document.getElementById('joinError');
    
    if (!roomName || !password) {
        errorEl.textContent = 'Room name and password are required';
        errorEl.classList.remove('hidden');
        return;
    }
    
    await window.chat.apiJoinRoom(roomName, password);
    closeJoinModal();
}

// Initialize chat when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.chat = new StreamzyChat();
});
