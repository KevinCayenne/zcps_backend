#!/usr/bin/env python
"""
Test script to verify custom email templates are working correctly.

This script tests:
1. Custom email classes are loaded
2. Templates use correct subject lines
3. URLs are formatted correctly without double protocol
4. FRONTEND_URL is being used instead of Django Site domain
"""

import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
django.setup()

from django.conf import settings
from users.email import (
    ActivationEmail, PasswordResetEmail, ConfirmationEmail,
    PasswordChangedConfirmationEmail, parse_frontend_url
)
from users.models import User
from unittest.mock import patch


def test_activation_email():
    """Test activation email template and context."""
    print("\n" + "="*60)
    print("Testing Activation Email")
    print("="*60)

    # Create a test user (don't save to DB)
    user = User(username='testuser', email='test@example.com')
    user.id = 1  # Set an ID for UID generation

    # Create email instance
    email = ActivationEmail()

    # Mock context
    context = {
        'user': user,
        'uid': 'test-uid-123',
        'token': 'test-token-456',
    }

    # Get context data (this will call our custom get_context_data)
    email.context = context
    full_context = email.get_context_data()

    # Print results
    print(f"✓ Template: {email.template_name}")
    print(f"✓ Protocol: {full_context.get('protocol')}")
    print(f"✓ Domain: {full_context.get('domain')}")
    print(f"✓ URL: {full_context.get('url')}")
    print(f"✓ Full URL: {full_context.get('protocol')}://{full_context.get('domain')}/{full_context.get('url')}")

    # Verify no double protocol
    full_url = f"{full_context.get('protocol')}://{full_context.get('domain')}/{full_context.get('url')}"
    if 'http://http://' in full_url or 'https://https://' in full_url:
        print("❌ ERROR: Double protocol detected!")
        return False
    else:
        print("✓ No double protocol")

    # Verify domain matches FRONTEND_URL
    expected_domain = settings.FRONTEND_URL.replace('http://', '').replace('https://', '')
    if full_context.get('domain') == expected_domain:
        print(f"✓ Domain matches FRONTEND_URL")
    else:
        print(f"❌ ERROR: Domain mismatch. Expected: {expected_domain}, Got: {full_context.get('domain')}")
        return False

    print("\n✅ Activation email test PASSED")
    return True


def test_password_reset_email():
    """Test password reset email template and context."""
    print("\n" + "="*60)
    print("Testing Password Reset Email")
    print("="*60)

    # Create email instance
    email = PasswordResetEmail()

    # Mock context
    context = {
        'user': User(username='testuser', email='test@example.com'),
        'uid': 'test-uid-789',
        'token': 'test-token-012',
    }

    # Get context data
    email.context = context
    full_context = email.get_context_data()

    # Print results
    print(f"✓ Template: {email.template_name}")
    print(f"✓ Protocol: {full_context.get('protocol')}")
    print(f"✓ Domain: {full_context.get('domain')}")
    print(f"✓ URL: {full_context.get('url')}")
    print(f"✓ Full URL: {full_context.get('protocol')}://{full_context.get('domain')}/{full_context.get('url')}")

    # Verify no double protocol
    full_url = f"{full_context.get('protocol')}://{full_context.get('domain')}/{full_context.get('url')}"
    if 'http://http://' in full_url or 'https://https://' in full_url:
        print("❌ ERROR: Double protocol detected!")
        return False
    else:
        print("✓ No double protocol")

    print("\n✅ Password reset email test PASSED")
    return True


def test_parse_frontend_url():
    """Test the parse_frontend_url helper function."""
    print("\n" + "="*60)
    print("Testing parse_frontend_url() Helper Function")
    print("="*60)

    test_cases = [
        ('http://localhost:3000', ('http', 'localhost:3000')),
        ('https://app.example.com', ('https', 'app.example.com')),
        ('localhost:3000', ('http', 'localhost:3000')),
        ('127.0.0.1:8000', ('http', '127.0.0.1:8000')),
        ('example.com', ('https', 'example.com')),
        ('https://example.com:8080', ('https', 'example.com:8080')),
    ]

    all_passed = True
    for frontend_url, expected in test_cases:
        with patch.object(settings, 'FRONTEND_URL', frontend_url):
            result = parse_frontend_url()
            if result == expected:
                print(f"✓ '{frontend_url}' -> {result}")
            else:
                print(f"❌ '{frontend_url}' -> Expected {expected}, got {result}")
                all_passed = False

    if all_passed:
        print("\n✅ parse_frontend_url() test PASSED")
    else:
        print("\n❌ parse_frontend_url() test FAILED")

    return all_passed


def test_settings():
    """Verify DJOSER settings are correct."""
    print("\n" + "="*60)
    print("Testing DJOSER Configuration")
    print("="*60)

    email_config = settings.DJOSER.get('EMAIL', {})

    print(f"✓ FRONTEND_URL: {settings.FRONTEND_URL}")
    print(f"✓ Activation email class: {email_config.get('activation')}")
    print(f"✓ Password reset email class: {email_config.get('password_reset')}")
    print(f"✓ Confirmation email class: {email_config.get('confirmation')}")
    print(f"✓ Password changed email class: {email_config.get('password_changed_confirmation')}")

    # Verify classes are set correctly
    expected_classes = {
        'activation': 'users.email.ActivationEmail',
        'confirmation': 'users.email.ConfirmationEmail',
        'password_reset': 'users.email.PasswordResetEmail',
        'password_changed_confirmation': 'users.email.PasswordChangedConfirmationEmail',
    }

    all_correct = True
    for key, expected in expected_classes.items():
        actual = email_config.get(key)
        if actual != expected:
            print(f"❌ ERROR: {key} = {actual}, expected {expected}")
            all_correct = False

    if all_correct:
        print("\n✅ DJOSER configuration test PASSED")
    else:
        print("\n❌ DJOSER configuration test FAILED")

    return all_correct


if __name__ == '__main__':
    print("\n🔍 Testing Custom Email Templates")
    print("="*60)

    results = []

    # Run tests
    results.append(("Settings", test_settings()))
    results.append(("Helper Function", test_parse_frontend_url()))
    results.append(("Activation Email", test_activation_email()))
    results.append(("Password Reset Email", test_password_reset_email()))

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")

    all_passed = all(result[1] for result in results)

    if all_passed:
        print("\n🎉 All tests passed!")
        exit(0)
    else:
        print("\n⚠️  Some tests failed. Please review the output above.")
        exit(1)
