"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include
from users.views import LogoutView

urlpatterns = [
    path('admin/', admin.site.urls),

    # Djoser authentication endpoints under /auth/ prefix
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),

    # Custom logout endpoint with token blacklisting
    path('auth/logout/', LogoutView.as_view(), name='logout'),
]
