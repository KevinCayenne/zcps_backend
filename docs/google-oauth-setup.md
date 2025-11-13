# Google OAuth Setup Guide

This guide will walk you through setting up Google OAuth 2.0 authentication for the Django boilerplate.

## Prerequisites

- A Google account
- Access to [Google Cloud Console](https://console.cloud.google.com/)

## Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click on the project dropdown in the top navigation bar
3. Click "New Project"
4. Enter a project name (e.g., "Django Auth Boilerplate")
5. Click "Create"
6. Wait for the project to be created and select it

## Step 2: Enable Google+ API (or Google Identity Services)

1. In the Google Cloud Console, go to "APIs & Services" > "Library"
2. Search for "Google+ API" or "Google Identity Services"
3. Click on the API
4. Click "Enable"
5. Wait for the API to be enabled

## Step 3: Create OAuth 2.0 Credentials

1. In the Google Cloud Console, go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. If prompted to configure the OAuth consent screen:
   - Click "Configure Consent Screen"
   - Choose "External" (or "Internal" if using Google Workspace)
   - Click "Create"
   - Fill in the required fields:
     - App name: "Django Auth Boilerplate"
     - User support email: Your email
     - Developer contact information: Your email
   - Click "Save and Continue"
   - Skip adding scopes (click "Save and Continue")
   - Skip adding test users (click "Save and Continue")
   - Click "Back to Dashboard"

4. Go back to "Credentials" and click "Create Credentials" > "OAuth client ID"
5. Select "Web application" as the application type
6. Enter a name (e.g., "Django Web Client")

## Step 4: Configure Authorized Redirect URIs

### Development Environment

Add the following redirect URI for local development:

```
http://localhost:8000/auth/google/callback/
```

### Production Environment

Add your production redirect URI:

```
https://api.yourdomain.com/auth/google/callback/
```

**Important:** Make sure to include the trailing slash (`/`) in the redirect URI.

### Additional Redirect URIs (Optional)

You can add multiple redirect URIs for different environments:

- Staging: `https://api-staging.yourdomain.com/auth/google/callback/`
- Development: `http://127.0.0.1:8000/auth/google/callback/`

## Step 5: Copy Your Credentials

1. After creating the OAuth client ID, you'll see a dialog with your credentials:
   - **Client ID**: A long string like `1234567890-abcdefghijklmnop.apps.googleusercontent.com`
   - **Client Secret**: A shorter string like `GOCSPX-AbCdEfGhIjKlMnOpQrStUvWx`

2. Copy these credentials - you'll need them for the next step

3. If you closed the dialog, you can always view them by:
   - Going to "APIs & Services" > "Credentials"
   - Clicking on your OAuth 2.0 Client ID name
   - Viewing the Client ID and Client Secret

## Step 6: Configure Environment Variables

Add the credentials to your `.env` file:

```env
# Google OAuth Configuration
GOOGLE_OAUTH_CLIENT_ID=your-actual-client-id-here
GOOGLE_OAUTH_CLIENT_SECRET=your-actual-client-secret-here

# OAuth Redirect URLs
GOOGLE_OAUTH_SUCCESS_REDIRECT_URL=http://localhost:3000/auth/callback
GOOGLE_OAUTH_ERROR_REDIRECT_URL=http://localhost:3000/auth/error
```

**Security Notes:**
- Never commit your `.env` file to version control
- Keep your client secret private
- Use different credentials for development and production
- Rotate your credentials periodically

## Step 7: Test the OAuth Flow

1. Start your Django development server:
   ```bash
   python manage.py runserver
   ```

2. Navigate to the OAuth initiation endpoint in your browser:
   ```
   http://localhost:8000/auth/google/
   ```

3. You should be redirected to Google's OAuth consent screen

4. Sign in with your Google account and grant permissions

5. You should be redirected back to your frontend with JWT tokens as query parameters

## Troubleshooting

### Error: "redirect_uri_mismatch"

**Problem:** The redirect URI in your request doesn't match any authorized redirect URIs.

**Solution:**
- Check that your redirect URI exactly matches one in the Google Cloud Console
- Ensure you included the trailing slash
- Verify you're using the correct protocol (http vs https)
- Check for typos in the redirect URI

### Error: "invalid_client"

**Problem:** Your client ID or client secret is incorrect.

**Solution:**
- Verify your credentials in the Google Cloud Console
- Check that you copied the entire client ID and secret
- Ensure there are no extra spaces or characters
- Make sure you're using credentials from the correct project

### Error: "access_denied"

**Problem:** User clicked "Cancel" on the OAuth consent screen.

**Solution:**
- This is expected behavior when users deny access
- Your app should handle this gracefully by redirecting to the error URL

### OAuth Consent Screen Shows Warning

**Problem:** Google shows a warning that the app is not verified.

**Solution:**
- For development, you can proceed anyway
- For production, submit your app for verification in the Google Cloud Console
- Add test users in the OAuth consent screen configuration to bypass the warning during development

## Testing with Test Users

During development, you can add test users to bypass the unverified app warning:

1. Go to "APIs & Services" > "OAuth consent screen"
2. Scroll down to "Test users"
3. Click "Add Users"
4. Enter email addresses of users who should be able to test the OAuth flow
5. Click "Save"

Test users will be able to authenticate without seeing the unverified app warning.

## Scopes Requested

This implementation requests the following minimal scopes:

- `openid`: Required for OpenID Connect
- `email`: User's email address
- `profile`: User's basic profile information (name, picture)

These scopes are sufficient for authentication and do not request access to any Google services (Calendar, Drive, etc.).

## Production Checklist

Before deploying to production:

- [ ] Create separate OAuth credentials for production
- [ ] Configure production redirect URIs in Google Cloud Console
- [ ] Update environment variables with production credentials
- [ ] Submit app for verification if needed
- [ ] Test the full OAuth flow in production environment
- [ ] Set up monitoring for OAuth errors
- [ ] Configure proper error handling and user messaging
- [ ] Ensure HTTPS is enabled for all OAuth endpoints
- [ ] Review and minimize requested scopes
- [ ] Set up credential rotation schedule

## Additional Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Google Cloud Console](https://console.cloud.google.com/)
- [OAuth 2.0 Playground](https://developers.google.com/oauthplayground/) - Test OAuth flows

## Support

If you encounter issues:

1. Check the server logs for detailed error messages
2. Review the OAuth callback URL for error parameters
3. Verify your Google Cloud Console configuration
4. Consult the Google OAuth documentation
5. Check that all required environment variables are set correctly
