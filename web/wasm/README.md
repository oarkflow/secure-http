# Secure WASM Demo - Login & Protected Assets

This demo showcases secure authentication and encrypted communication using WebAssembly (WASM) based cryptography.

## 🎯 Demo Features

### 1. **User Authentication**
- Login page with credential validation
- Pre-configured demo accounts (user-123 / user-token-123)
- Session establishment with device registration
- JWT token generation for stateless authentication

### 2. **Secure Session Management**
- HMAC-based session keys
- End-to-end encryption using WASM
- Automatic handshake with server
- Session state tracking and validation

### 3. **Protected Asset Loading**
- Secure asset directory (web/wasm/assets/)
- Authentication required for all asset access
- Encrypted data transfer
- Audit logging for asset access

### 4. **Secure API Fetch**
- All API requests encrypted via WASM
- Support for GET, POST, PUT, DELETE methods
- Real-time activity logging
- Session-based request authentication

## 📁 File Structure

```
web/wasm/
├── login.html          # Authentication page
├── demo.html           # Protected demo area
├── demo.js            # Demo logic & WASM integration
├── wasm_exec.js       # Go WASM runtime
├── main.wasm          # Compiled WASM binary
└── assets/            # Protected assets directory
    ├── data.json      # Sample data
    ├── config.json    # Application config
    ├── report.json    # Security report
    └── README.md      # Assets documentation
```

## 🚀 Getting Started

### Step 1: Start the Server

```bash
# From the project root
go run cmd/fullstack/main.go
```

The server will start on `http://localhost:8443` (or configured port).

### Step 2: Access the Demo

Open your browser and navigate to:
```
http://localhost:8443/wasm/login.html
```

### Step 3: Login

Use the pre-configured demo credentials:
- **User ID**: `user-123`
- **User Token**: `user-token-123`

Alternative account:
- **User ID**: `user-456`
- **User Token**: `user-token-456`

### Step 4: Explore the Demo

After successful login, you'll be redirected to the demo page where you can:

1. **View Session Information**
   - See your authenticated session details
   - Monitor session status and expiration

2. **Test Secure API Calls**
   - Select HTTP method (GET, POST, PUT, DELETE)
   - Enter API endpoint (e.g., `/api/echo`)
   - Execute encrypted requests
   - View encrypted responses

3. **Load Protected Assets**
   - Click "Refresh Assets" to load secure resources
   - Assets are fetched through encrypted channels
   - View asset contents by clicking on them

4. **Monitor Activity**
   - Real-time activity log
   - See all security events
   - Track successful/failed operations

## 🔐 Security Flow

### Authentication Flow
```
1. User enters credentials on login.html
2. POST /login → Server validates user token
3. Server derives device secret & registers device
4. Server returns:
   - Device ID & Secret
   - Gate secrets
   - Capability token
   - JWT access & refresh tokens
5. Client stores auth config in sessionStorage
6. Client redirects to demo.html
```

### Secure Fetch Flow
```
1. Demo page loads WASM module
2. WASM initializes with auth config
3. Client performs handshake with server
4. Session keys established
5. All subsequent requests:
   - Encrypted by WASM before sending
   - Include gate headers (HMAC signatures)
   - Include session authentication
   - Decrypted by server
   - Response encrypted by server
   - Response decrypted by WASM
```

### Asset Loading Flow
```
1. User clicks "Refresh Assets"
2. Client makes GET requests to /api/assets/:filename
3. Requests are encrypted end-to-end
4. Server validates session & authentication
5. Server logs asset access for audit
6. Asset content returned (encrypted)
7. WASM decrypts response
8. Client displays asset content
```

## 📊 API Endpoints

### Public Endpoints
- `POST /login` - User authentication

### Protected Endpoints (require auth & encryption)
- `POST /api/echo` - Echo test endpoint
- `POST /api/user/info` - User information
- `POST /api/login` - Secure login confirmation
- `POST /api/session/state` - Session status
- `GET /api/assets/:filename` - Protected asset loading
- `POST /api/logout` - Session termination

## 🧪 Testing the Demo

### Test 1: Basic Authentication
```javascript
// Navigate to login page
// Enter: user-123 / user-token-123
// Should redirect to demo.html
```

### Test 2: Secure API Call
```javascript
// In demo page:
// Method: POST
// Endpoint: /api/echo
// Click "Execute Request"
// Should see encrypted response with security envelope
```

### Test 3: Asset Loading
```javascript
// In demo page:
// Click "Refresh Assets"
// Should load: data.json, config.json, report.json
// Click on any asset to view contents
```

### Test 4: Session Management
```javascript
// View session info in top card
// Check session ID, device ID, status
// All requests should show in activity log
```

## 🔧 Configuration

### Server Configuration
Edit `config/server.json`:
```json
{
  "listen_addr": ":8443",
  "auth": {
    "jwt_signing_key": "your-secure-key"
  },
  "gate": {
    "secrets": [...],
    "allowed_origins": [...]
  }
}
```

### User Accounts
Edit `config/accounts.json`:
```json
{
  "accounts": [
    {
      "id": "owner",
      "userID": "user-123",
      "userToken": "user-token-123",
      "roles": ["admin", "device-owner"]
    }
  ]
}
```

## 🎨 Customization

### Adding New Assets
1. Create file in `web/wasm/assets/`
2. Assets automatically protected by authentication
3. Access via `/api/assets/your-file.json`

### Adding New API Endpoints
1. Add handler in `cmd/fullstack/main.go`
2. Register in `registerSecureRoutes()`
3. Endpoint automatically encrypted

### Customizing UI
- `login.html` - Login page styling & behavior
- `demo.html` - Demo page layout
- `demo.js` - Demo functionality & WASM integration

## 🐛 Troubleshooting

### WASM Not Loading
- Check that `main.wasm` exists in `web/wasm/`
- Check browser console for errors
- Verify WASM mime type is served correctly

### Authentication Fails
- Verify credentials in `config/accounts.json`
- Check server logs for validation errors
- Clear sessionStorage and try again

### Assets Not Loading
- Verify assets exist in `web/wasm/assets/`
- Check server logs for path errors
- Verify session is authenticated

### Session Expired
- Logout and login again
- Check session timeout configuration
- Verify gate headers are being sent

## 📝 Notes

- All communication is encrypted end-to-end
- Session keys are ephemeral and rotated
- Gate signatures prevent replay attacks
- Audit logs track all security events
- Assets are only accessible after authentication
- Session expires after configured timeout

## 🔗 Related Documentation

- [Main README](../../README.md) - Project overview
- [Assets README](assets/README.md) - Asset directory details
- [Config Documentation](../../config/) - Configuration files

## 📄 License

Part of the secure-http project.
