#!/usr/bin/env python
"""
Quick configuration test script for Google OAuth and Email setup.
Run this to verify your environment variables are configured correctly.
"""

import os
import sys

import django
from django.conf import settings
from django.core.mail import send_mail

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")
django.setup()


def test_email_config():
    """Test email configuration."""
    print("\n" + "=" * 60)
    print("📧 EMAIL CONFIGURATION TEST")
    print("=" * 60)

    print(f"✓ EMAIL_BACKEND: {settings.EMAIL_BACKEND}")

    if "console" in settings.EMAIL_BACKEND:
        print("✓ Using console backend (emails will print to terminal)")
        print("  → No SMTP credentials needed for testing")
    elif "smtp" in settings.EMAIL_BACKEND:
        print("✓ Using SMTP backend")
        print(f"  → EMAIL_HOST: {getattr(settings, 'EMAIL_HOST', 'Not set')}")
        print(f"  → EMAIL_PORT: {getattr(settings, 'EMAIL_PORT', 'Not set')}")
        print(f"  → EMAIL_HOST_USER: {getattr(settings, 'EMAIL_HOST_USER', 'Not set')}")
        print(
            f"  → EMAIL_HOST_PASSWORD: {'***set***' if getattr(settings, 'EMAIL_HOST_PASSWORD', '') else 'NOT SET'}"
        )

    print(f"✓ DEFAULT_FROM_EMAIL: {settings.DEFAULT_FROM_EMAIL}")

    # Try sending test email
    try:
        print("\n📤 Sending test email...")
        send_mail(
            "Test Email from Django Boilerplate",
            "This is a test email to verify email configuration.",
            settings.DEFAULT_FROM_EMAIL,
            ["test@example.com"],
            fail_silently=False,
        )
        print("✅ Test email sent successfully!")
        if "console" in settings.EMAIL_BACKEND:
            print("   Check your terminal output above for the email content.")
    except Exception as e:
        print(f"❌ Failed to send test email: {e}")
        return False

    return True


def test_google_oauth():
    """Test Google OAuth configuration."""
    print("\n" + "=" * 60)
    print("🔐 GOOGLE OAUTH CONFIGURATION TEST")
    print("=" * 60)

    client_id = (
        settings.SOCIALACCOUNT_PROVIDERS.get("google", {})
        .get("APP", {})
        .get("client_id", "")
    )
    client_secret = (
        settings.SOCIALACCOUNT_PROVIDERS.get("google", {})
        .get("APP", {})
        .get("secret", "")
    )

    print(
        f"✓ GOOGLE_OAUTH_CLIENT_ID: {client_id[:20]}..." if client_id else "❌ NOT SET"
    )
    print(
        f"✓ GOOGLE_OAUTH_CLIENT_SECRET: {'***set***' if client_secret else '❌ NOT SET'}"
    )
    print(f"✓ Success Redirect: {settings.GOOGLE_OAUTH_SUCCESS_REDIRECT_URL}")
    print(f"✓ Error Redirect: {settings.GOOGLE_OAUTH_ERROR_REDIRECT_URL}")

    if not client_id or not client_secret:
        print("\n⚠️  Google OAuth credentials not configured!")
        print("   Follow the setup guide to configure Google OAuth.")
        return False

    print("\n✅ Google OAuth configuration looks good!")
    print("\n🔗 Test OAuth by visiting: http://localhost:8000/auth/google/")

    return True


def test_frontend_url():
    """Test frontend URL configuration."""
    print("\n" + "=" * 60)
    print("🌐 FRONTEND URL CONFIGURATION TEST")
    print("=" * 60)

    print(f"✓ FRONTEND_URL: {settings.FRONTEND_URL}")
    print("  (Used for password reset and activation links)")

    return True


if __name__ == "__main__":
    print("\n🧪 DJANGO AUTH BOILERPLATE - CONFIGURATION TEST")
    print("=" * 60)

    results = []
    results.append(test_email_config())
    results.append(test_google_oauth())
    results.append(test_frontend_url())

    print("\n" + "=" * 60)
    if all(results):
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        print("\n📝 Next steps:")
        print("1. Start the development server: python manage.py runserver")
        print("2. Test user registration at: http://localhost:8000/api/docs/")
        print("3. Check terminal for activation emails (console backend)")
        print("4. Test Google OAuth at: http://localhost:8000/auth/google/")
    else:
        print("⚠️  SOME TESTS FAILED - Check configuration above")
        print("=" * 60)
        sys.exit(1)
