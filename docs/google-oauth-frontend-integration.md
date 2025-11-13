# Google OAuth Frontend Integration Guide

This guide explains how to integrate Google OAuth authentication with your frontend application.

## Overview

The OAuth flow consists of three main steps:

1. **Initiation**: Frontend redirects user to backend OAuth endpoint
2. **Authorization**: User authorizes on Google's consent screen
3. **Callback**: Backend redirects back to frontend with JWT tokens

## OAuth Flow Diagram

```
Frontend ──► Backend (/auth/google/) ──► Google OAuth Consent Screen
                                              │
                                              ▼
Frontend ◄── Backend (with tokens) ◄── Google Authorization Server
```

## Step 1: Initiate OAuth Flow

From your frontend, redirect the user to the backend OAuth initiation endpoint:

### JavaScript/React Example

```javascript
const handleGoogleLogin = () => {
  // Redirect to backend OAuth endpoint
  window.location.href = 'http://localhost:8000/auth/google/';
};

// In your component
<button onClick={handleGoogleLogin}>
  Sign in with Google
</button>
```

### Vue.js Example

```javascript
export default {
  methods: {
    handleGoogleLogin() {
      window.location.href = 'http://localhost:8000/auth/google/';
    }
  }
}

// In your template
<button @click="handleGoogleLogin">Sign in with Google</button>
```

### Angular Example

```typescript
export class LoginComponent {
  handleGoogleLogin(): void {
    window.location.href = 'http://localhost:8000/auth/google/';
  }
}

// In your template
<button (click)="handleGoogleLogin()">Sign in with Google</button>
```

## Step 2: Handle Successful Callback

After successful authentication, the backend redirects to your frontend callback URL with JWT tokens as query parameters:

```
http://localhost:3000/auth/callback?access=<access_token>&refresh=<refresh_token>
```

### React Example

```javascript
import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

const OAuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const accessToken = searchParams.get('access');
    const refreshToken = searchParams.get('refresh');

    if (accessToken && refreshToken) {
      // Store tokens in localStorage or state management
      localStorage.setItem('access_token', accessToken);
      localStorage.setItem('refresh_token', refreshToken);

      // Optionally fetch user info
      fetchUserInfo(accessToken);

      // Redirect to dashboard or home
      navigate('/dashboard');
    } else {
      // Handle missing tokens
      console.error('No tokens received from OAuth callback');
      navigate('/login');
    }
  }, [searchParams, navigate]);

  return <div>Processing authentication...</div>;
};

const fetchUserInfo = async (accessToken) => {
  try {
    const response = await fetch('http://localhost:8000/auth/users/me/', {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    const userData = await response.json();
    console.log('User info:', userData);
    // Store user info in state/context
  } catch (error) {
    console.error('Error fetching user info:', error);
  }
};

export default OAuthCallback;
```

### Vue.js Example

```javascript
export default {
  name: 'OAuthCallback',
  mounted() {
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken = urlParams.get('access');
    const refreshToken = urlParams.get('refresh');

    if (accessToken && refreshToken) {
      // Store tokens
      localStorage.setItem('access_token', accessToken);
      localStorage.setItem('refresh_token', refreshToken);

      // Fetch user info
      this.fetchUserInfo(accessToken);

      // Redirect to dashboard
      this.$router.push('/dashboard');
    } else {
      console.error('No tokens received');
      this.$router.push('/login');
    }
  },
  methods: {
    async fetchUserInfo(accessToken) {
      try {
        const response = await fetch('http://localhost:8000/auth/users/me/', {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        });
        const userData = await response.json();
        this.$store.commit('setUser', userData);
      } catch (error) {
        console.error('Error fetching user info:', error);
      }
    }
  }
};
```

## Step 3: Handle Error Callback

If OAuth fails, the backend redirects to your error URL with error details:

```
http://localhost:3000/auth/error?error_type=<type>&error_message=<message>
```

### React Example

```javascript
import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

const OAuthError = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [errorInfo, setErrorInfo] = useState({ type: '', message: '' });

  useEffect(() => {
    const errorType = searchParams.get('error_type');
    const errorMessage = searchParams.get('error_message');

    setErrorInfo({
      type: errorType || 'unknown',
      message: errorMessage || 'An unknown error occurred'
    });
  }, [searchParams]);

  const handleRetry = () => {
    navigate('/login');
  };

  return (
    <div className="error-container">
      <h2>Authentication Failed</h2>
      <p><strong>Error Type:</strong> {errorInfo.type}</p>
      <p><strong>Message:</strong> {errorInfo.message}</p>
      <button onClick={handleRetry}>Back to Login</button>
    </div>
  );
};

export default OAuthError;
```

## Error Types

The backend may return the following error types:

- `access_denied`: User clicked "Cancel" on Google consent screen
- `invalid_credentials`: Invalid OAuth client ID or secret (backend configuration issue)
- `server_error`: Network error or unexpected backend error
- `invalid_request`: Missing authorization code or invalid request
- `oauth_error`: Other OAuth-related errors from Google

## Using JWT Tokens for API Requests

After storing the access token, include it in the Authorization header for all authenticated requests:

### Axios Example (React/Vue)

```javascript
import axios from 'axios';

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add request interceptor to include token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Handle token refresh on 401
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem('refresh_token');
        const response = await axios.post('http://localhost:8000/auth/jwt/refresh/', {
          refresh: refreshToken
        });

        const { access } = response.data;
        localStorage.setItem('access_token', access);

        originalRequest.headers.Authorization = `Bearer ${access}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        // Refresh failed, redirect to login
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default apiClient;
```

### Fetch Example

```javascript
const fetchWithAuth = async (url, options = {}) => {
  const token = localStorage.getItem('access_token');

  const headers = {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` }),
    ...options.headers
  };

  const response = await fetch(url, {
    ...options,
    headers
  });

  if (response.status === 401) {
    // Token expired, try to refresh
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      // Retry original request
      return fetchWithAuth(url, options);
    } else {
      // Refresh failed, redirect to login
      window.location.href = '/login';
    }
  }

  return response;
};

const refreshAccessToken = async () => {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) return false;

  try {
    const response = await fetch('http://localhost:8000/auth/jwt/refresh/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh: refreshToken })
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('access_token', data.access);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Token refresh failed:', error);
    return false;
  }
};
```

## Environment Configuration

Configure your frontend environment variables for different environments:

### Development (.env.development)

```
REACT_APP_API_URL=http://localhost:8000
REACT_APP_OAUTH_CALLBACK_URL=http://localhost:3000/auth/callback
REACT_APP_OAUTH_ERROR_URL=http://localhost:3000/auth/error
```

### Production (.env.production)

```
REACT_APP_API_URL=https://api.yourdomain.com
REACT_APP_OAUTH_CALLBACK_URL=https://yourdomain.com/auth/callback
REACT_APP_OAUTH_ERROR_URL=https://yourdomain.com/auth/error
```

## Security Best Practices

1. **Token Storage**: Store tokens in localStorage or sessionStorage, not in cookies (to avoid CSRF)
2. **HTTPS Only**: Always use HTTPS in production
3. **Token Refresh**: Implement automatic token refresh before expiration
4. **Logout**: Clear tokens on logout:
   ```javascript
   const handleLogout = () => {
     localStorage.removeItem('access_token');
     localStorage.removeItem('refresh_token');
     // Optionally call backend logout endpoint
     navigate('/login');
   };
   ```
5. **Token Validation**: Always validate tokens on the backend
6. **XSS Protection**: Sanitize all user input to prevent XSS attacks

## Testing OAuth Flow Locally

1. Start your Django backend:
   ```bash
   python manage.py runserver
   ```

2. Start your frontend development server:
   ```bash
   npm start  # React
   # or
   npm run serve  # Vue
   # or
   ng serve  # Angular
   ```

3. Navigate to your frontend login page and click "Sign in with Google"

4. Complete the OAuth flow on Google's consent screen

5. Verify that tokens are received and stored correctly

6. Test making authenticated API requests

## Complete React Router Example

```javascript
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Login from './pages/Login';
import OAuthCallback from './pages/OAuthCallback';
import OAuthError from './pages/OAuthError';
import Dashboard from './pages/Dashboard';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/auth/callback" element={<OAuthCallback />} />
        <Route path="/auth/error" element={<OAuthError />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
```

## Troubleshooting

### Tokens not appearing in callback URL

- Check backend logs for errors
- Verify OAuth credentials are configured correctly
- Ensure redirect URI matches Google Cloud Console configuration

### CORS errors

- Configure CORS in Django settings to allow your frontend origin
- Add `CORS_ALLOWED_ORIGINS` in settings:
  ```python
  CORS_ALLOWED_ORIGINS = [
      "http://localhost:3000",
      "http://127.0.0.1:3000",
  ]
  ```

### Token refresh not working

- Verify refresh token is being stored
- Check that refresh endpoint is correct
- Ensure refresh token hasn't expired (7 days by default)

## Additional Resources

- [React Router Documentation](https://reactrouter.com/)
- [Vue Router Documentation](https://router.vuejs.org/)
- [Axios Documentation](https://axios-http.com/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
