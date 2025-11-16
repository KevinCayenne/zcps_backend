# Google OAuth Testing Guide

This guide explains how to test Google OAuth authentication using the included `users/static/test_pages/oauth_test.html` page.

## Prerequisites

1. **Google OAuth credentials configured**: Ensure `.env` has valid credentials
   ```bash
   GOOGLE_OAUTH_CLIENT_ID=your-client-id
   GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret
   ```

2. **Redirect URLs configured**: The `.env` should point to the test page
   ```bash
   GOOGLE_OAUTH_SUCCESS_REDIRECT_URL=http://localhost:3000/oauth_test.html
   GOOGLE_OAUTH_ERROR_REDIRECT_URL=http://localhost:3000/oauth_test.html
   ```

## How to Test

### Quick Start

You need to run **two servers simultaneously** to test OAuth:

1. **Terminal 1 - Start the backend (Django)**:
   ```bash
   python manage.py runserver
   # Runs on http://localhost:8000
   ```

2. **Terminal 2 - Start the frontend (HTTP server)**:
   ```bash
   cd users/static/test_pages
   python3 -m http.server 3000
   # Runs on http://localhost:3000
   ```

3. **Open your browser**:
   - Navigate to: `http://localhost:3000/oauth_test.html`
   - Click "Sign in with Google"
   - Authorize with your Google account
   - You'll be redirected back with JWT tokens displayed

### Why Two Servers?

This setup mimics a real production environment where:
- **Backend (Django on :8000)**: Handles OAuth, API endpoints, database
- **Frontend (HTTP server on :3000)**: Serves the HTML/JS/CSS

This is how you'd run a real app locally (e.g., React on :3000, Django on :8000) and ensures the OAuth flow works exactly as it would in production.

### Features

#### 1. Token Display
- **Access Token**: Short-lived token (default: 15 minutes)
- **Refresh Token**: Long-lived token (default: 7 days)
- Both can be copied to clipboard with one click

#### 2. Decode Token
Click "Decode Token" to see the JWT payload contents:
- User ID
- Token expiration time
- Token type
- Other claims

The tool will also alert you how many minutes until the token expires.

#### 3. Test API
Click "Test API with Token" to verify the access token works:
- Makes a request to `/auth/users/me/`
- Displays your user profile data
- Shows any authentication errors

#### 4. Test Refresh
Click "Test Refresh" to get a new access token:
- Uses the refresh token to get a new access token
- Automatically updates the displayed access token
- Useful for testing token expiration and renewal

#### 5. 2FA Flow (if enabled)

If you have 2FA enforcement enabled in Django admin (`/admin/users/twofactorsettings/`) or the user has 2FA enabled:

1. After Google OAuth, you'll see the "2FA Required" screen
2. A temporary token is displayed
3. Check your email for the 6-digit verification code
4. Enter the code in the form and click "Verify Code"
5. Upon success, you'll receive full JWT tokens

### Testing Scenarios

#### Test 1: Basic Authentication
1. Start with a fresh session (click "Test Again" if needed)
2. Click "Sign in with Google"
3. Verify you get access and refresh tokens
4. Click "Test API" to confirm the token works

#### Test 2: Token Refresh
1. Complete Test 1
2. Click "Decode Token" and note the expiration time
3. Wait a few minutes
4. Click "Test Refresh"
5. Click "Decode Token" again and verify new expiration time

#### Test 3: Token Expiration
1. Complete Test 1
2. Wait 15+ minutes for access token to expire
3. Click "Test API" - should fail with 401 error
4. Click "Test Refresh" to get new access token
5. Click "Test API" - should now succeed

#### Test 4: 2FA Authentication
1. Enable 2FA in your account or enable 2FA enforcement in Django admin (`/admin/users/twofactorsettings/`)
2. Click "Sign in with Google"
3. Verify you see the "2FA Required" screen
4. Check your email for the verification code
5. Enter the code and click "Verify Code"
6. Verify you receive full JWT tokens

#### Test 5: Error Handling
1. Start the OAuth flow
2. Deny access when Google asks for permissions
3. Verify you see a friendly error message
4. Click "Try Again" to restart

## Troubleshooting

### "Failed to fetch" Error
- **Cause**: Django server is not running
- **Fix**: Start server with `python manage.py runserver`

### "Invalid token" Error
- **Cause**: Token has expired or is malformed
- **Fix**: Click "Test Again" and re-authenticate

### OAuth Redirect Loop
- **Cause**: Redirect URLs in `.env` don't match the test page location
- **Fix**: Update `GOOGLE_OAUTH_SUCCESS_REDIRECT_URL` to the correct file path

### 2FA Code Not Received
- **Cause**: Email configuration issue
- **Fix**: Check `.env` email settings and verify SMTP credentials

### "Access Denied" Error
- **Cause**: You denied Google authorization
- **Fix**: Click "Try Again" and grant permissions

## API Endpoints Used

The test page interacts with these endpoints:

- `GET /auth/google/` - Initiate OAuth flow
- `GET /auth/google/callback/` - OAuth callback (handled automatically)
- `GET /auth/users/me/` - Get current user profile
- `POST /auth/jwt/refresh/` - Refresh access token
- `POST /auth/2fa/verify/` - Verify 2FA code

## How It Works (Technical Details)

### Two-Server Architecture

This setup uses two separate HTTP servers running simultaneously:

1. **Backend Server (Django on port 8000)**:
   - Handles OAuth flow
   - Manages user authentication
   - Provides API endpoints
   - Generates JWT tokens

2. **Frontend Server (Python HTTP server on port 3000)**:
   - Serves the HTML test page
   - Makes requests to the backend
   - Displays OAuth results

This architecture mirrors a real production setup where your frontend (React, Vue, etc.) and backend (Django) are separate applications.

### The OAuth Flow

Here's the complete flow when you test Google OAuth:

```
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Open Test Page in Browser                            │
│  ─────────────────────────────────────────────────────────────  │
│  You: Navigate to http://localhost:3000/oauth_test.html        │
│  Frontend: Serves the HTML page                                │
│  Page: Shows "Sign in with Google" button                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: Start OAuth                                           │
│  ─────────────────────────────────────────────────────────────  │
│  You: Click "Sign in with Google"                              │
│  JavaScript: window.location = 'http://localhost:8000/auth/google/' │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: Backend Redirects to Google                           │
│  ─────────────────────────────────────────────────────────────  │
│  Backend: GET /auth/google/                                     │
│  Backend: Redirects to https://accounts.google.com/o/oauth2/...│
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 4: Google Authorization                                  │
│  ─────────────────────────────────────────────────────────────  │
│  You: Select Google account & grant permissions                │
│  Google: Redirects to http://localhost:8000/auth/google/callback/?code=ABC │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 5: Backend Creates JWT Tokens                            │
│  ─────────────────────────────────────────────────────────────  │
│  Backend: GET /auth/google/callback/?code=ABC                  │
│  Backend: Exchanges code for Google user info                  │
│  Backend: Creates/finds user in database                       │
│  Backend: Generates JWT access + refresh tokens                │
│  Backend: Redirects to http://localhost:3000/oauth_test.html?access=...&refresh=... │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 6: Frontend Displays Tokens                              │
│  ─────────────────────────────────────────────────────────────  │
│  Frontend: Serves oauth_test.html?access=...&refresh=...       │
│  JavaScript: Extracts tokens from URL query parameters         │
│  Page: Displays tokens + shows "Test API" button               │
└─────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- Browser navigates: `http://localhost:3000` → `http://localhost:8000` → `https://google.com` → `http://localhost:8000` → back to `http://localhost:3000`
- Backend's final redirect includes the JWT tokens as URL parameters
- JavaScript reads the URL parameters and displays the tokens
- All communication uses standard HTTP protocol (no file:// URLs)

### Why This Approach Is Better

- ✅ **Production-like**: Mimics real deployment with separate frontend/backend
- ✅ **Standard HTTP**: Uses normal HTTP protocol for all requests
- ✅ **No custom code**: Django uses standard redirect security
- ✅ **Easy transition**: Same code works in development and production (just change URLs)
- ✅ **Proper CORS**: Can test cross-origin requests if needed

## Security Notes

⚠️ **This test page is for development only!**

- JWT tokens are displayed in plain text for debugging
- Uses localhost URLs (not accessible from internet)
- Never commit your `.env` file with real OAuth credentials to git
- In production, use HTTPS and proper frontend security

## Transitioning to Production

When deploying your app:

1. **Update `.env` with production URLs**:
   ```bash
   GOOGLE_OAUTH_SUCCESS_REDIRECT_URL=https://yourdomain.com/auth/callback
   GOOGLE_OAUTH_ERROR_REDIRECT_URL=https://yourdomain.com/auth/error
   ```

2. **Deploy your frontend** (React, Vue, etc.):
   - Implement token storage (localStorage/sessionStorage with security measures)
   - Add proper error handling UI
   - Implement automatic token refresh before expiration
   - Add logout functionality that clears stored tokens

3. **Update Google OAuth settings**:
   - Add production redirect URI to Google Cloud Console
   - Example: `https://api.yourdomain.com/auth/google/callback/`

4. **No backend code changes needed**:
   - The OAuth implementation works identically in production
   - Only the redirect URLs change (from localhost to your domain)
