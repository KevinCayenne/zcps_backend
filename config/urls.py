"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include
from users.views import LogoutView
from users.oauth_views import oauth_login, GoogleCallback
from users.twofactor_views import (
    enable_2fa, verify_setup_2fa, disable_2fa, get_2fa_status,
    verify_2fa_login, resend_2fa_code
)
from users.jwt_views import CustomTokenObtainPairView, CustomTokenRefreshView, CustomTokenVerifyView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

urlpatterns = [
    path('admin/', admin.site.urls),

    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # Allauth URLs (required for OAuth views)
    path('accounts/', include('allauth.urls')),

    # Custom Djoser endpoints with JWT token blacklisting
    path('auth/', include('users.urls')),

    # Custom JWT login endpoint with 2FA support
    path('auth/jwt/create/', CustomTokenObtainPairView.as_view(), name='jwt-create'),
    path('auth/jwt/refresh/', CustomTokenRefreshView.as_view(), name='jwt-refresh'),
    path('auth/jwt/verify/', CustomTokenVerifyView.as_view(), name='jwt-verify'),

    # Custom logout endpoint with token blacklisting
    path('auth/logout/', LogoutView.as_view(), name='logout'),

    # Google OAuth endpoints
    path('auth/google/', oauth_login, name='google_login'),
    path('auth/google/callback/', GoogleCallback.as_view(), name='google_callback'),

    # Two-Factor Authentication endpoints
    path('auth/2fa/enable/', enable_2fa, name='2fa_enable'),
    path('auth/2fa/enable/verify/', verify_setup_2fa, name='2fa_verify_setup'),
    path('auth/2fa/disable/', disable_2fa, name='2fa_disable'),
    path('auth/2fa/status/', get_2fa_status, name='2fa_status'),
    path('auth/2fa/verify/', verify_2fa_login, name='2fa_verify_login'),
    path('auth/2fa/resend/', resend_2fa_code, name='2fa_resend'),
]
