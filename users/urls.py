"""
Custom URL configuration for users app.

Provides custom Djoser endpoints that include JWT token blacklisting
functionality for password management operations.
"""

from django.urls import path, re_path
from .views import CustomUserViewSet, VerifyEmailView, SendRegistrationOTPView, VerifyRegistrationOTPView, LogoutView

urlpatterns = [
    # Email verification (must come before users/)
    path('users/verify-email/', VerifyEmailView.as_view(), name='user-verify-email'),
    path('users/send-registration-otp/', SendRegistrationOTPView.as_view(), name='user-send-registration-otp'),
    path('users/verify-registration-otp/', VerifyRegistrationOTPView.as_view(), name='user-verify-registration-otp'),
    
    # Logout endpoint
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Password management (must come before users/me/)
    path('users/set_password/', CustomUserViewSet.as_view({'post': 'set_password'}), name='user-set-password'),
    path('users/reset_password/', CustomUserViewSet.as_view({'post': 'reset_password'}), name='user-reset-password'),
    path('users/reset_password_confirm/', CustomUserViewSet.as_view({'post': 'reset_password_confirm'}), name='user-reset-password-confirm'),

    # Email activation (must come before users/me/)
    path('users/activation/', CustomUserViewSet.as_view({'post': 'activation'}), name='user-activation'),
    path('users/resend_activation/', CustomUserViewSet.as_view({'post': 'resend_activation'}), name='user-resend-activation'),

    # Current user detail
    path('users/me/', CustomUserViewSet.as_view({'get': 'me', 'put': 'me', 'patch': 'me', 'delete': 'me'}), name='user-me'),

    # User detail by id (must come before users/)
    re_path(r'^users/(?P<id>\d+)/$', CustomUserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='user-detail'),

    # User creation and list
    path('users/', CustomUserViewSet.as_view({'post': 'create', 'get': 'list'}), name='user-list'),
]
