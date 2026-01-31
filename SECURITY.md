# Streamzy Security Considerations

## 🔐 Encryption

### Message Encryption
- All chat messages are encrypted using **Fernet** (AES-128-CBC with HMAC)
- Each message is encrypted before storage in the database
- Decryption only occurs when messages are retrieved for display
- The encryption key should be stored securely in environment variables

### Key Management
```bash
# Generate a new encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Important:** 
- Never commit the encryption key to version control
- Rotate keys periodically (requires re-encryption of all messages)
- Backup keys securely - lost keys mean unrecoverable messages

## 🔑 Authentication

### Password Security
- Passwords are hashed using **bcrypt** with 12 rounds
- System-generated passwords are 16 characters with mixed character types
- Failed login attempts are tracked and accounts are locked after 5 failures
- Account lockout duration: 15 minutes

### Session Management
- Sessions expire after 2 hours of inactivity
- Session tokens are cryptographically random (64 bytes)
- Sessions are invalidated on logout
- Activity timeout triggers automatic logout (30 minutes default)

## 🛡️ Attack Prevention

### SQL Injection
- All database queries use SQLAlchemy ORM with parameterized queries
- Input validation rejects suspicious patterns
- No raw SQL queries are used

### Cross-Site Scripting (XSS)
- All user input is HTML-escaped before display
- Content Security Policy headers restrict script sources
- Input validation detects and blocks XSS patterns

### Cross-Site Request Forgery (CSRF)
- Flask-WTF provides CSRF protection
- All POST/PUT/DELETE requests require valid CSRF tokens
- Tokens are rotated per session

### Rate Limiting
- Login attempts: 10 per 5 minutes
- Application submissions: 5 per 5 minutes
- Messages: 30 per minute
- API endpoints: 100 per hour

## 📊 Audit Logging

The following events are logged:
- User logins (success/failure)
- User logouts
- Application submissions
- Application approvals/rejections
- Password changes
- User account changes
- Blocked messages (security violations)
- Failed authentication attempts

Logs include:
- Timestamp
- User ID (if authenticated)
- IP address
- User agent
- Event description

## 🌐 Network Security

### Production Recommendations

1. **Always use HTTPS**
   - WebSocket connections should use WSS
   - Set `SESSION_COOKIE_SECURE=True`

2. **Reverse Proxy**
   - Use Nginx or similar as a reverse proxy
   - Handle SSL/TLS termination at the proxy
   - Forward real IP addresses

3. **Firewall**
   - Only expose necessary ports (443 for HTTPS)
   - Block direct access to the application port

4. **Headers**
   ```nginx
   add_header X-Frame-Options "DENY";
   add_header X-Content-Type-Options "nosniff";
   add_header X-XSS-Protection "1; mode=block";
   add_header Referrer-Policy "strict-origin-when-cross-origin";
   ```

## ⚠️ Known Limitations

1. **Single Encryption Key**
   - All messages use the same key
   - Key rotation requires message re-encryption

2. **Server-Side Decryption**
   - True E2E would require client-side decryption
   - Server can technically read decrypted messages

3. **In-Memory Rate Limiting**
   - Rate limits reset on server restart
   - Not shared across multiple instances

4. **SQLite Database**
   - Not suitable for high-traffic production
   - Consider PostgreSQL for production

## 🔄 Security Checklist

Before deploying to production:

- [ ] Change default admin password
- [ ] Generate new SECRET_KEY
- [ ] Generate new ENCRYPTION_KEY
- [ ] Configure HTTPS/SSL
- [ ] Set `FLASK_ENV=production`
- [ ] Set `FLASK_DEBUG=0`
- [ ] Set `SESSION_COOKIE_SECURE=True`
- [ ] Configure firewall rules
- [ ] Set up log monitoring
- [ ] Enable database backups
- [ ] Review and test rate limits
- [ ] Remove any test accounts
- [ ] Audit all admin accounts

## 📞 Reporting Security Issues

If you discover a security vulnerability, please:
1. Do NOT create a public GitHub issue
2. Contact the maintainers privately
3. Provide detailed steps to reproduce
4. Allow time for a fix before disclosure

---

Remember: Security is a process, not a product. Regular audits and updates are essential.
