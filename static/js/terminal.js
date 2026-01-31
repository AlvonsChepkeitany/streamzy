/**
 * Streamzy Terminal Utilities
 * Common terminal UI functions
 */

const Terminal = {
    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Format timestamp
     */
    formatTime(date) {
        if (typeof date === 'string') {
            date = new Date(date);
        }
        return date.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    },

    /**
     * Create a message line element
     */
    createMessageLine(options) {
        const { username, content, timestamp, type = 'message', isSelf = false } = options;
        
        const line = document.createElement('div');
        line.className = `message-line ${type === 'system' ? 'system-message' : ''}`;
        
        const timeStr = timestamp ? this.formatTime(timestamp) : this.formatTime(new Date());
        
        line.innerHTML = `
            <span class="timestamp">[${timeStr}]</span>
            <span class="username ${isSelf ? 'self' : ''} ${type === 'system' ? 'system' : ''}">${this.escapeHtml(username)}:</span>
            <span class="content">${this.escapeHtml(content)}</span>
        `;
        
        return line;
    },

    /**
     * Create a system message line
     */
    createSystemLine(content, type = 'info') {
        const line = document.createElement('div');
        line.className = `output-line ${type}`;
        
        const timeStr = this.formatTime(new Date());
        const promptText = type === 'error' ? 'ERROR' : 'SYSTEM';
        
        line.innerHTML = `
            <span class="timestamp">[${timeStr}]</span>
            <span class="prompt">${promptText}://</span>
            <span class="text">${this.escapeHtml(content)}</span>
        `;
        
        return line;
    },

    /**
     * Create a command response element
     */
    createCommandResponse(response) {
        const div = document.createElement('div');
        div.className = 'command-response';
        div.textContent = response;
        return div;
    },

    /**
     * Scroll element to bottom
     */
    scrollToBottom(element) {
        if (element) {
            element.scrollTop = element.scrollHeight;
        }
    },

    /**
     * Play typing sound effect (optional)
     */
    playKeySound() {
        // Could add subtle typing sound here
    },

    /**
     * Typing animation for text
     */
    typeText(element, text, speed = 50) {
        return new Promise((resolve) => {
            let index = 0;
            element.textContent = '';
            
            const interval = setInterval(() => {
                if (index < text.length) {
                    element.textContent += text[index];
                    index++;
                } else {
                    clearInterval(interval);
                    resolve();
                }
            }, speed);
        });
    },

    /**
     * Boot sequence animation
     */
    async bootSequence(lines, container, delay = 500) {
        for (const line of lines) {
            const element = this.createSystemLine(line);
            container.appendChild(element);
            this.scrollToBottom(container);
            await new Promise(r => setTimeout(r, delay));
        }
    },

    /**
     * Matrix rain effect (background decoration)
     */
    initMatrixRain(canvas) {
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()_+-=[]{}|;:,.<>?';
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        
        const drops = [];
        for (let i = 0; i < columns; i++) {
            drops[i] = 1;
        }
        
        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.fillStyle = '#00ff00';
            ctx.font = `${fontSize}px monospace`;
            
            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        
        setInterval(draw, 35);
    },

    /**
     * Glitch effect on element
     */
    glitchEffect(element, duration = 500) {
        element.classList.add('glitch');
        setTimeout(() => element.classList.remove('glitch'), duration);
    },

    /**
     * Sound notification
     */
    playNotification() {
        // Could play a subtle notification sound
        if ('vibrate' in navigator) {
            navigator.vibrate(50);
        }
    }
};

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Terminal;
}
