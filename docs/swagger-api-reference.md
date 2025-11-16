# Swagger API Reference & Usage Guide

This document provides detailed usage instructions for testing all endpoints using Swagger UI.

## Access Swagger UI

- **Swagger UI:** http://localhost:8000/api/docs/
- **ReDoc:** http://localhost:8000/api/redoc/
- **OpenAPI Schema:** http://localhost:8000/api/schema/

---

## Table of Contents

1. [Getting Started with Swagger](#getting-started-with-swagger)
2. [Authentication in Swagger](#authentication-in-swagger)
3. [Endpoint Categories](#endpoint-categories)
4. [Common Request Examples](#common-request-examples)
5. [Testing Workflows](#testing-workflows)

---

## Getting Started with Swagger

Navigate to `http://localhost:8000/api/docs/` in your browser.

Endpoints are organized by tags:
- **Authentication** - Login, logout, token management
- **Two-Factor Authentication** - 2FA setup and verification
- **User Management** - User registration and profile management

---

## Authentication in Swagger

Most endpoints require authentication. Here's how to authenticate in Swagger:

### Step 1: Obtain JWT Token

1. Expand `POST /auth/jwt/create/`
2. Click "Try it out"
3. Enter credentials:
```json
{
  "email": "your_email@example.com",
  "password": "your_password"
}
```
4. Click "Execute"
5. Copy the `access` token from the response

### Step 2: Authorize in Swagger

1. Click the **"Authorize"** button at the top right
2. In the "bearerAuth" section, paste your token:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```
3. Click "Authorize"
4. Click "Close"

**Now all authenticated endpoints will include your token automatically!**

### Step 3: Test Authenticated Endpoint

Try `GET /auth/users/me/` to verify authentication works:
1. Expand the endpoint
2. Click "Try it out"
3. Click "Execute"
4. You should see your user profile data

---

## Endpoint Categories

### Authentication Endpoints

| Endpoint | Method | Auth Required | Description |
|----------|--------|---------------|-------------|
| `/auth/jwt/create/` | POST | No | Login and obtain JWT tokens |
| `/auth/jwt/refresh/` | POST | No | Refresh access token |
| `/auth/jwt/verify/` | POST | No | Verify token validity |
| `/auth/logout/` | POST | Yes | Logout and blacklist token |
| `/auth/google/` | GET | No | Initiate Google OAuth flow |

### Two-Factor Authentication Endpoints

| Endpoint | Method | Auth Required | Description |
|----------|--------|---------------|-------------|
| `/auth/2fa/enable/` | POST | Yes | Initiate 2FA setup |
| `/auth/2fa/enable/verify/` | POST | Yes | Verify and complete 2FA setup |
| `/auth/2fa/disable/` | POST | Yes | Disable 2FA |
| `/auth/2fa/status/` | GET | Yes | Check 2FA status |
| `/auth/2fa/verify/` | POST | Yes* | Verify 2FA code during login |
| `/auth/2fa/resend/` | POST | Yes* | Resend 2FA code |

*Uses temporary token from login response

### User Management Endpoints

| Endpoint | Method | Auth Required | Description |
|----------|--------|---------------|-------------|
| `/auth/users/` | POST | No | Register new user |
| `/auth/users/me/` | GET | Yes | Get current user profile |
| `/auth/users/me/` | PUT/PATCH | Yes | Update user profile |
| `/auth/users/me/` | DELETE | Yes | Delete user account |
| `/auth/users/activation/` | POST | No | Activate user account |
| `/auth/users/resend_activation/` | POST | No | Resend activation email |
| `/auth/users/reset_password/` | POST | No | Request password reset |
| `/auth/users/reset_password_confirm/` | POST | No | Confirm password reset |
| `/auth/users/set_password/` | POST | Yes | Change password |

---

## Common Request Examples

### 1. Register New User

**Endpoint:** `POST /auth/users/`

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1 555 123 4567"
}
```

**Expected Response:** `201 Created`
```json
{
  "id": 1,
  "username": "johndoe",
  "email": "john@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1 555 123 4567",
  "created_at": "2025-11-15T12:00:00Z"
}
```

**Usage in Swagger:**
1. Expand `POST /auth/users/`
2. Click "Try it out"
3. Paste the request body above
4. Click "Execute"
5. Check the response

---

### 2. Login (Without 2FA)

**Endpoint:** `POST /auth/jwt/create/`

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response:** `200 OK`
```json
{
  "access": "eyJ0eXAiOiJKV1Qi...",
  "refresh": "eyJ0eXAiOiJKV1Qi..."
}
```

**Next Steps:**
- Copy the `access` token
- Click "Authorize" button
- Paste token and authorize
- Now you can test authenticated endpoints

---

### 3. Login (With 2FA Enabled)

**Endpoint:** `POST /auth/jwt/create/`

**Request Body:** (same as above)

**Expected Response:** `200 OK`
```json
{
  "temp_token": "eyJ0eXAiOiJKV1Qi...",
  "requires_2fa": true,
  "message": "Verification code sent to your email. Please verify to complete login.",
  "expires_at": "2025-11-15T12:10:00Z"
}
```

**Next Steps:**
1. Check your email for 6-digit code
2. Copy the `temp_token`
3. Authorize in Swagger with temp token
4. Use `POST /auth/2fa/verify/` with the code
5. Get full JWT tokens

---

### 4. Enable Two-Factor Authentication

**Endpoint:** `POST /auth/2fa/enable/`

**Prerequisites:**
- Must be authenticated (use "Authorize" button with access token)

**Request Body:**
```json
{
  "method": "email"
}
```

**Expected Response:** `200 OK`
```json
{
  "message": "Verification code sent to your email. Please verify to enable 2FA.",
  "method": "email",
  "expires_at": "2025-11-15T12:20:00Z"
}
```

**Next Steps:**
1. Check email for 6-digit code
2. Use `POST /auth/2fa/enable/verify/` with the code
3. 2FA is now enabled

---

### 5. Verify 2FA Setup

**Endpoint:** `POST /auth/2fa/enable/verify/`

**Prerequisites:**
- Must have called `/auth/2fa/enable/` first
- Must be authenticated

**Request Body:**
```json
{
  "code": "123456"
}
```

**Expected Response:** `200 OK`
```json
{
  "message": "2FA has been successfully enabled for your account.",
  "enabled_at": "2025-11-15T12:15:00Z"
}
```

---

### 6. Verify 2FA During Login

**Endpoint:** `POST /auth/2fa/verify/`

**Prerequisites:**
- Received `temp_token` from login
- Authorized in Swagger with temp token

**Request Body:**
```json
{
  "code": "654321"
}
```

**Expected Response:** `200 OK`
```json
{
  "access": "eyJ0eXAiOiJKV1Qi...",
  "refresh": "eyJ0eXAiOiJKV1Qi...",
  "message": "2FA verification successful."
}
```

**Next Steps:**
- Replace temp token with new access token in Swagger
- Continue using authenticated endpoints

---

### 7. Check 2FA Status

**Endpoint:** `GET /auth/2fa/status/`

**Prerequisites:** Must be authenticated

**Expected Response:** `200 OK`
```json
{
  "is_2fa_enabled": true,
  "twofa_setup_date": "2025-11-15T12:15:00Z",
  "preferred_2fa_method": "EMAIL"
}
```

---

### 8. Disable Two-Factor Authentication

**Endpoint:** `POST /auth/2fa/disable/`

**Prerequisites:** Must be authenticated

**Request Body:**
```json
{
  "password": "SecurePass123!"
}
```

**Expected Response:** `200 OK`
```json
{
  "message": "2FA has been disabled for your account."
}
```

---

### 9. Get Current User Profile

**Endpoint:** `GET /auth/users/me/`

**Prerequisites:** Must be authenticated

**No request body needed**

**Expected Response:** `200 OK`
```json
{
  "id": 1,
  "username": "johndoe",
  "email": "john@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1 555 123 4567",
  "created_at": "2025-11-15T12:00:00Z"
}
```

---

### 10. Update User Profile

**Endpoint:** `PATCH /auth/users/me/`

**Prerequisites:** Must be authenticated

**Request Body:** (partial update)
```json
{
  "first_name": "Johnny",
  "phone_number": "+1 555 999 8888"
}
```

**Expected Response:** `200 OK` (updated user object)

---

### 11. Request Password Reset

**Endpoint:** `POST /auth/users/reset_password/`

**No authentication required**

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

**Expected Response:** `204 No Content`

**Next Steps:**
- Check email for reset link
- Extract `uid` and `token` from link
- Use `/auth/users/reset_password_confirm/`

---

### 12. Confirm Password Reset

**Endpoint:** `POST /auth/users/reset_password_confirm/`

**Request Body:**
```json
{
  "uid": "MQ",
  "token": "c0h1i9-abc123def456...",
  "new_password": "NewSecurePass456!"
}
```

**Expected Response:** `204 No Content`

**Important:** All existing tokens are blacklisted. User must login again.

---

### 13. Refresh Access Token

**Endpoint:** `POST /auth/jwt/refresh/`

**Request Body:**
```json
{
  "refresh": "eyJ0eXAiOiJKV1Qi..."
}
```

**Expected Response:** `200 OK`
```json
{
  "access": "eyJ0eXAiOiJKV1Qi..."
}
```

---

### 14. Logout

**Endpoint:** `POST /auth/logout/`

**Prerequisites:** Must be authenticated

**Request Body:**
```json
{
  "refresh": "eyJ0eXAiOiJKV1Qi..."
}
```

**Expected Response:** `204 No Content`

**Important:** Refresh token is blacklisted. You must login again to get new tokens.

---

## Testing Workflows

### Workflow 1: New User Registration and Login

1. **Register:** `POST /auth/users/`
2. **Login:** `POST /auth/jwt/create/` → Get tokens
3. **Authorize** in Swagger with access token
4. **Get Profile:** `GET /auth/users/me/`

---

### Workflow 2: Enable and Test 2FA

1. **Login:** `POST /auth/jwt/create/` → Get tokens
2. **Authorize** in Swagger
3. **Enable 2FA:** `POST /auth/2fa/enable/`
4. Check email for code
5. **Verify Setup:** `POST /auth/2fa/enable/verify/` with code
6. **Logout:** `POST /auth/logout/`
7. **Login Again:** `POST /auth/jwt/create/` → Get temp_token
8. **Authorize** with temp token
9. Check email for new code
10. **Verify 2FA:** `POST /auth/2fa/verify/` → Get full tokens
11. **Re-authorize** with new access token

---

### Workflow 3: Password Reset

1. **Request Reset:** `POST /auth/users/reset_password/`
2. Check email for reset link
3. Extract `uid` and `token` from link
4. **Confirm Reset:** `POST /auth/users/reset_password_confirm/`
5. **Login** with new password

---

### Workflow 4: OAuth Login (Browser Required)

1. Open `http://localhost:8000/auth/google/` in browser
2. Authorize with Google
3. Get redirected to frontend with tokens in URL
4. Extract `access` token from URL
5. **Authorize** in Swagger with access token
6. Test authenticated endpoints

---

## Tips for Testing in Swagger

### 1. Copy Tokens Easily

When you receive tokens in responses:
- Click on the token value
- It will be highlighted
- Copy with Ctrl+C / Cmd+C

### 2. Check Email in Console

In development mode, emails are printed to console:
```bash
# Check terminal where server is running
# You'll see email content with codes
```

### 3. Decode JWT Tokens

Copy any JWT token and paste it at https://jwt.io to see:
- User ID
- Expiration time
- Token type (access, refresh, temp_2fa)

### 4. Monitor Server Logs

Watch the terminal for:
- Request/response details
- Validation errors
- Database queries
- Email sending confirmation

### 5. Clear Authorization

To test unauthenticated endpoints or switch users:
1. Click "Authorize" button
2. Click "Logout" button
3. Re-authorize with different token

### 6. Test Error Scenarios

Try invalid inputs to test error handling:
- Wrong password
- Expired codes
- Missing required fields
- Invalid token formats

### 7. Use Django Admin for State

Check database state in Django admin:
- User accounts and 2FA status
- TwoFactorCode entries
- Blacklisted tokens
- TwoFactorSettings configuration

http://localhost:8000/admin/

---

## Common Issues

### "Unauthorized" Errors

**Problem:** Getting 401 responses on authenticated endpoints

**Solution:**
1. Check if token is expired (decode at jwt.io)
2. Re-authorize with fresh access token
3. If using temp token, only `/auth/2fa/verify/` and `/auth/2fa/resend/` work

---

### "Invalid or expired verification code"

**Problem:** 2FA failing

**Solution:**
1. Check email for correct code
2. Ensure code hasn't expired (10 minutes default)
3. Don't use the same code twice
4. Request new code with resend endpoint

---

### OAuth Endpoints Not Working in Swagger

**Problem:** `/auth/google/` doesn't work in Swagger UI

**Solution:**
- OAuth requires browser redirects
- Open `http://localhost:8000/auth/google/` directly in browser
- Swagger is for testing JSON API endpoints only

---

### CSRF Token Errors

**Problem:** Getting CSRF errors

**Solution:**
- This is a REST API with JWT authentication
- CSRF is disabled for API endpoints
- Make sure you're using `/auth/` prefix
- Check that `Content-Type: application/json` header is set

---

## Quick Reference

### Response Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | Success with data | Login successful |
| 201 | Resource created | User registered |
| 204 | Success no data | Logout successful |
| 400 | Bad request | Invalid input |
| 401 | Unauthorized | Invalid/missing token |
| 403 | Forbidden | 2FA required |
| 404 | Not found | Endpoint doesn't exist |
| 501 | Not implemented | Phone 2FA |

### Token Types

| Type | Use Case | Lifetime | Endpoints |
|------|----------|----------|-----------|
| Access | Regular API calls | 15 min | Most endpoints |
| Refresh | Get new access token | 7 days | `/auth/jwt/refresh/` |
| Temporary | 2FA verification only | 10 min | `/auth/2fa/verify/`, `/auth/2fa/resend/` |

### Code Types

| Type | Purpose | Lifetime | Length |
|------|---------|----------|--------|
| 2FA Login | Verify during login | 10 min | 6 digits |
| 2FA Setup | Enable 2FA | 10 min | 6 digits |

---

For detailed testing scenarios and workflows, see [Manual Testing Workflows](./manual-testing-workflows.md).
