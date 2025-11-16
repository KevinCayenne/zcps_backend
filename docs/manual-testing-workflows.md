# Manual Testing Workflows & Scenarios

This document provides comprehensive testing workflows for all authentication endpoints. Each scenario includes step-by-step instructions, expected requests/responses, and validation points.

## Table of Contents

1. [User Registration & Email Verification](#1-user-registration--email-verification)
2. [Login Without 2FA](#2-login-without-2fa)
3. [Login With 2FA Enabled](#3-login-with-2fa-enabled)
4. [Google OAuth Login](#4-google-oauth-login)
5. [Enable Two-Factor Authentication](#5-enable-two-factor-authentication)
6. [Disable Two-Factor Authentication](#6-disable-two-factor-authentication)
7. [Password Reset Flow](#7-password-reset-flow)
9. [Token Refresh & Verification](#9-token-refresh--verification)
10. [Logout & Token Blacklisting](#10-logout--token-blacklisting)
11. [2FA Enforcement Scenarios](#11-2fa-enforcement-scenarios)
12. [Error Scenarios](#12-error-scenarios)

---

## Prerequisites

- Server running at `http://localhost:8000`
- Swagger UI available at `http://localhost:8000/api/docs/`
- Email backend configured (check console for emails in development)
- Access to Django admin at `http://localhost:8000/admin/`

---

## 1. User Registration & Email Verification

### Scenario 1.1: Register New User (Email Verification Disabled)

**Endpoint:** `POST /auth/users/`

**Request:**
```json
{
  "username": "testuser1",
  "email": "testuser1@example.com",
  "password": "SecurePass123!",
  "first_name": "Test",
  "last_name": "User",
  "phone_number": "+1 234 567 8901"
}
```

**Expected Response:** `201 Created`
```json
{
  "id": 1,
  "username": "testuser1",
  "email": "testuser1@example.com",
  "first_name": "Test",
  "last_name": "User",
  "phone_number": "+1 234 567 8901"
}
```

**Validation:**
- ✅ User created in database
- ✅ No activation email sent (if `SEND_ACTIVATION_EMAIL=False`)

---

### Scenario 1.2: Register New User (Email Verification Enabled)

**Endpoint:** `POST /auth/users/`

**Request:** (Same as above)

**Expected Response:** `201 Created`

**Email Sent:**
```
Subject: Activate your account
Body: Click the link to activate: http://localhost:3000/activate?uid=XXX&token=YYY
```

**Activation Endpoint:** `POST /auth/users/activation/`

**Activation Request:**
```json
{
  "uid": "XXX",
  "token": "YYY"
}
```

**Expected Response:** `204 No Content`

**Validation:**
- ✅ User account is now active
- ✅ User can log in
- ✅ `is_active` field is `True` in database

---

## 2. Login Without 2FA

### Scenario 2.1: Standard Email/Password Login

**Endpoint:** `POST /auth/jwt/create/`

**Request:**
```json
{
  "email": "testuser1@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response:** `200 OK`
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Validation:**
- ✅ Access token expires in 15 minutes (default)
- ✅ Refresh token expires in 7 days (default)
- ✅ Tokens can be decoded with `jwt.io`
- ✅ Access token contains `user_id`, `email`, `exp`, `iat`

---

### Scenario 2.2: Login With Username

**Endpoint:** `POST /auth/jwt/create/`

**Request:**
```json
{
  "username": "testuser1",
  "password": "SecurePass123!"
}
```

**Expected Response:** `200 OK` (same as 2.1)

**Validation:**
- ✅ Username and email are interchangeable for login

---

### Scenario 2.3: Login With Invalid Credentials

**Endpoint:** `POST /auth/jwt/create/`

**Request:**
```json
{
  "email": "testuser1@example.com",
  "password": "WrongPassword"
}
```

**Expected Response:** `401 Unauthorized`
```json
{
  "error": "Invalid credentials."
}
```

---

## 3. Login With 2FA Enabled

### Scenario 3.1: Login Triggers 2FA Code

**Prerequisites:** User has 2FA enabled (see Section 5)

**Endpoint:** `POST /auth/jwt/create/`

**Request:**
```json
{
  "email": "testuser1@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response:** `200 OK`
```json
{
  "temp_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "requires_2fa": true,
  "message": "Verification code sent to your email. Please verify to complete login.",
  "expires_at": "2025-11-15T12:25:00Z"
}
```

**Email Sent:**
```
Subject: Your 2FA Verification Code
Body: Your verification code is: 123456
This code expires in 10 minutes.
```

**Validation:**
- ✅ Temporary token is valid for 10 minutes
- ✅ Temporary token has `temp_2fa: true` claim
- ✅ 6-digit code sent to user's email
- ✅ Code expires in 10 minutes (configurable)

---

### Scenario 3.2: Verify 2FA Code

**Endpoint:** `POST /auth/2fa/verify/`

**Request Headers:**
```
Authorization: Bearer {temp_token}
```

**Request Body:**
```json
{
  "code": "123456"
}
```

**Expected Response:** `200 OK`
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "message": "2FA verification successful."
}
```

**Validation:**
- ✅ Full JWT tokens returned
- ✅ Temporary token is no longer valid
- ✅ 2FA code is marked as used in database
- ✅ `last_2fa_verification` timestamp updated on User

---

### Scenario 3.3: Verify 2FA With Incorrect Code

**Endpoint:** `POST /auth/2fa/verify/`

**Request:**
```json
{
  "code": "999999"
}
```

**Expected Response:** `400 Bad Request`
```json
{
  "error": "Invalid or expired verification code."
}
```

**Validation:**
- ✅ `failed_attempts` incremented in TwoFactorCode
- ✅ After 5 failed attempts, code is locked
- ✅ User must request new code

---

### Scenario 3.4: Resend 2FA Code

**Endpoint:** `POST /auth/2fa/resend/`

**Request Headers:**
```
Authorization: Bearer {temp_token}
```

**Expected Response:** `200 OK`
```json
{
  "message": "New verification code sent to your email.",
  "expires_at": "2025-11-15T12:35:00Z"
}
```

**Validation:**
- ✅ Old code is invalidated (`is_used=True`)
- ✅ New 6-digit code generated and sent
- ✅ New expiration time set

---

## 4. Google OAuth Login

### Scenario 4.1: Initiate OAuth Flow

**Endpoint:** `GET /auth/google/`

**Browser Action:**
1. Open `http://localhost:8000/auth/google/` in browser
2. Redirected to Google consent screen
3. User authorizes app

**Validation:**
- ✅ Redirected to Google OAuth consent page
- ✅ Requested scopes: `openid`, `profile`, `email`

---

### Scenario 4.2: OAuth Callback (New User, No 2FA Enforcement)

**Endpoint:** `GET /auth/google/callback/` (handled automatically)

**Expected Redirect:**
```
http://localhost:3000/auth/callback?access=eyJ...&refresh=eyJ...
```

**Validation:**
- ✅ New user created with Google ID
- ✅ Email auto-verified (`email_verified=True`)
- ✅ Profile picture URL saved
- ✅ Password is unusable (OAuth-only account initially)
- ✅ Full JWT tokens in redirect URL

---

### Scenario 4.3: OAuth Callback (Existing User by Email)

**Prerequisites:** User with email `test@gmail.com` already exists

**Expected Behavior:**
- ✅ Google account linked to existing user
- ✅ `google_id` added to existing user record
- ✅ User can now log in with both password and OAuth
- ✅ JWT tokens returned

---

### Scenario 4.4: OAuth With 2FA Enforcement Enabled

**Prerequisites:**
- User has 2FA enabled
- `TwoFactorSettings.enforce_2fa_for_all_users = True`

**Expected Redirect:**
```
http://localhost:3000/auth/callback?temp_token=eyJ...&requires_2fa=true&expires_at=2025-11-15T12:45:00Z
```

**Email Sent:** 2FA verification code

**Next Steps:**
- User must verify 2FA code at `POST /auth/2fa/verify/`

**Validation:**
- ✅ OAuth users respect 2FA enforcement
- ✅ Temporary token provided instead of full tokens
- ✅ 2FA code sent to email

---

### Scenario 4.5: OAuth Error (User Denies Access)

**Browser Action:** User clicks "Deny" on Google consent screen

**Expected Redirect:**
```
http://localhost:3000/auth/error?error=access_denied&message=You+denied+access+to+your+Google+account.
```

**Validation:**
- ✅ Error gracefully handled
- ✅ No user created
- ✅ Clear error message

---

## 5. Enable Two-Factor Authentication

### Scenario 5.1: Enable 2FA (Email Method)

**Endpoint:** `POST /auth/2fa/enable/`

**Request Headers:**
```
Authorization: Bearer {access_token}
```

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
  "expires_at": "2025-11-15T12:55:00Z"
}
```

**Email Sent:**
```
Subject: Enable Two-Factor Authentication
Body: Your verification code is: 456789
```

**Validation:**
- ✅ 6-digit code sent to email
- ✅ User's `is_2fa_enabled` still `False` (pending verification)
- ✅ Code expires in 10 minutes

---

### Scenario 5.2: Verify 2FA Setup

**Endpoint:** `POST /auth/2fa/enable/verify/`

**Request Headers:**
```
Authorization: Bearer {access_token}
```

**Request Body:**
```json
{
  "code": "456789"
}
```

**Expected Response:** `200 OK`
```json
{
  "message": "2FA has been successfully enabled for your account.",
  "enabled_at": "2025-11-15T12:50:00Z"
}
```

**Validation:**
- ✅ `is_2fa_enabled=True` in database
- ✅ `twofa_setup_date` set to current timestamp
- ✅ `preferred_2fa_method='EMAIL'` saved
- ✅ Future logins will require 2FA

---

### Scenario 5.3: Enable 2FA (Phone Method - Not Implemented)

**Endpoint:** `POST /auth/2fa/enable/`

**Request Body:**
```json
{
  "method": "phone"
}
```

**Expected Response:** `501 Not Implemented`
```json
{
  "error": "Phone 2FA coming soon. Please use email method for now."
}
```

---

## 6. Disable Two-Factor Authentication

### Scenario 6.1: Disable 2FA

**Endpoint:** `POST /auth/2fa/disable/`

**Request Headers:**
```
Authorization: Bearer {access_token}
```

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

**Validation:**
- ✅ `is_2fa_enabled=False` in database
- ✅ Password verification required for security
- ✅ `twofa_setup_date` cleared
- ✅ Future logins won't require 2FA

---

### Scenario 6.2: Disable 2FA With Wrong Password

**Endpoint:** `POST /auth/2fa/disable/`

**Request Body:**
```json
{
  "password": "WrongPassword"
}
```

**Expected Response:** `400 Bad Request`
```json
{
  "error": "Invalid password."
}
```

---

## 7. Password Reset Flow

### Scenario 7.1: Request Password Reset

**Endpoint:** `POST /auth/users/reset_password/`

**Request:**
```json
{
  "email": "testuser1@example.com"
}
```

**Expected Response:** `204 No Content`

**Email Sent:**
```
Subject: Password Reset Request
Body: Click the link to reset your password: http://localhost:3000/reset-password?uid=XXX&token=YYY
```

**Validation:**
- ✅ Email sent even if user doesn't exist (security)
- ✅ Token expires in 24 hours (configurable)
- ✅ Token is single-use

---

### Scenario 7.2: Confirm Password Reset

**Endpoint:** `POST /auth/users/reset_password_confirm/`

**Request:**
```json
{
  "uid": "XXX",
  "token": "YYY",
  "new_password": "NewSecurePass456!"
}
```

**Expected Response:** `204 No Content`

**Validation:**
- ✅ Password changed successfully
- ✅ **All refresh tokens blacklisted** (forced logout)
- ✅ User must log in again with new password
- ✅ Token becomes invalid after use

---

## 9. Token Refresh & Verification

### Scenario 9.1: Refresh Access Token

**Endpoint:** `POST /auth/jwt/refresh/`

**Request:**
```json
{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Expected Response:** `200 OK`
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Validation:**
- ✅ New access token issued
- ✅ Refresh token remains valid
- ✅ Access token expires in 15 minutes

---

### Scenario 9.2: Verify Token Validity

**Endpoint:** `POST /auth/jwt/verify/`

**Request:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Expected Response:** `200 OK` (if valid)

**Expected Response:** `401 Unauthorized` (if expired/invalid)
```json
{
  "detail": "Token is invalid or expired",
  "code": "token_not_valid"
}
```

---

## 10. Logout & Token Blacklisting

### Scenario 10.1: Logout

**Endpoint:** `POST /auth/logout/`

**Request Headers:**
```
Authorization: Bearer {access_token}
```

**Request Body:**
```json
{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Expected Response:** `204 No Content`

**Validation:**
- ✅ Refresh token added to blacklist
- ✅ Token can no longer be used for refresh
- ✅ Access token still valid until expiration (stateless)

---

### Scenario 10.2: Try Using Blacklisted Token

**Endpoint:** `POST /auth/jwt/refresh/`

**Request:**
```json
{
  "refresh": "{blacklisted_token}"
}
```

**Expected Response:** `401 Unauthorized`
```json
{
  "detail": "Token is blacklisted",
  "code": "token_not_valid"
}
```

---

## 11. 2FA Enforcement Scenarios

### Scenario 11.1: Enable System-Wide 2FA Enforcement

**Django Admin:**
1. Go to `http://localhost:8000/admin/`
2. Navigate to "Two-Factor Authentication Settings"
3. Check "Enforce 2FA for all users"
4. Save

**Validation:**
- ✅ `TwoFactorSettings.enforce_2fa_for_all_users = True`

---

### Scenario 11.2: User Without 2FA Tries to Login (Enforcement Enabled)

**Endpoint:** `POST /auth/jwt/create/`

**Request:**
```json
{
  "email": "user_no_2fa@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response:** `403 Forbidden`
```json
{
  "error": "Two-factor authentication is required. Please enable 2FA at /auth/2fa/enable/",
  "required_action": "enable_2fa"
}
```

**Validation:**
- ✅ Login blocked
- ✅ Clear error message
- ✅ User directed to enable 2FA

---

### Scenario 11.3: User Enables 2FA Then Logs In

**Steps:**
1. User enables 2FA (see Section 5)
2. User logs in again

**Expected Response:** `200 OK` with `temp_token` (2FA flow)

**Validation:**
- ✅ User can now log in (with 2FA)
- ✅ System enforcement satisfied

---

## 12. Error Scenarios

### Scenario 12.1: Missing Required Fields

**Endpoint:** `POST /auth/users/`

**Request:**
```json
{
  "email": "test@example.com"
}
```

**Expected Response:** `400 Bad Request`
```json
{
  "username": ["This field is required."],
  "password": ["This field is required."]
}
```

---

### Scenario 12.2: Duplicate Email Registration

**Endpoint:** `POST /auth/users/`

**Request:**
```json
{
  "username": "newuser",
  "email": "testuser1@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response:** `400 Bad Request`
```json
{
  "email": ["A user with this email already exists."]
}
```

---

### Scenario 12.3: Expired 2FA Code

**Endpoint:** `POST /auth/2fa/verify/`

**Request:** (with code older than 10 minutes)

**Expected Response:** `400 Bad Request`
```json
{
  "error": "Invalid or expired verification code."
}
```

---

### Scenario 12.4: Using Temporary Token for Regular Endpoints

**Endpoint:** `GET /auth/users/me/`

**Request Headers:**
```
Authorization: Bearer {temp_token}
```

**Expected Response:** `401 Unauthorized`

**Validation:**
- ✅ Temporary tokens only work for 2FA verification endpoints
- ✅ Regular endpoints reject temp tokens

---

## Testing Checklist

### Pre-Testing Setup
- [ ] Server running
- [ ] Database migrated
- [ ] Email backend configured
- [ ] Admin user created
- [ ] Swagger UI accessible

### Core Flows
- [ ] User registration
- [ ] Email verification
- [ ] Login without 2FA
- [ ] Login with 2FA
- [ ] OAuth login
- [ ] Password reset
- [ ] Token refresh
- [ ] Logout

### 2FA Flows
- [ ] Enable 2FA
- [ ] Verify 2FA setup
- [ ] Disable 2FA
- [ ] 2FA login flow
- [ ] Resend 2FA code
- [ ] Failed 2FA attempts

### Admin Configuration
- [ ] 2FA enforcement toggle
- [ ] 2FA method defaults
- [ ] Code expiration settings
- [ ] View active 2FA users

### Error Handling
- [ ] Invalid credentials
- [ ] Expired codes
- [ ] Duplicate registrations
- [ ] Missing required fields
- [ ] Blacklisted tokens

---

## Notes

- All timestamps are in UTC
- Email contents visible in console during development
- Use Swagger UI for interactive testing
- Check Django admin for database state
- Monitor server logs for detailed error information

---

## Quick Reference

### Common Headers
```
Authorization: Bearer {access_token}
Content-Type: application/json
```

### Common Response Codes
- `200 OK` - Success with response body
- `201 Created` - Resource created
- `204 No Content` - Success without response body
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Invalid/missing authentication
- `403 Forbidden` - Authenticated but not authorized
- `501 Not Implemented` - Feature not yet available

### Testing Tools
- Swagger UI: `http://localhost:8000/api/docs/`
- Django Admin: `http://localhost:8000/admin/`
- ReDoc: `http://localhost:8000/api/redoc/`
- JWT Decoder: `https://jwt.io`
