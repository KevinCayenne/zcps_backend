"""
Admin interface configuration for User model.
"""

import json
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model
from django.contrib import messages
from solo.admin import SingletonModelAdmin

from users.models import TwoFactorCode, TwoFactorSettings

User = get_user_model()


@admin.register(TwoFactorSettings)
class TwoFactorSettingsAdmin(SingletonModelAdmin):
    """Admin interface for TwoFactorSettings singleton model."""

    fieldsets = (
        ('Enforcement Policy', {
            'fields': ('enforce_2fa_for_all_users', 'default_2fa_method'),
            'description': 'Configure system-wide 2FA enforcement and default method'
        }),
        ('Code Settings', {
            'fields': ('code_expiration_seconds',),
            'description': 'Configure verification code expiration time'
        }),
        ('Security Limits', {
            'fields': ('max_failed_attempts', 'temporary_token_lifetime_minutes'),
            'description': 'Configure security thresholds for failed attempts and token lifetime'
        }),
        ('Status', {
            'fields': ('active_2fa_users_count',),
            'description': 'Current 2FA adoption statistics'
        }),
    )

    readonly_fields = ('active_2fa_users_count',)

    actions = ['preview_config_as_json']

    def active_2fa_users_count(self, obj):
        """Display count of users with 2FA enabled."""
        count = User.objects.filter(is_2fa_enabled=True).count()
        return f"{count} users"
    active_2fa_users_count.short_description = "Currently Active Users with 2FA"

    def preview_config_as_json(self, request, queryset):
        """Preview current 2FA configuration as JSON."""
        settings_obj = TwoFactorSettings.get_solo()
        config_dict = {
            'enforce_2fa_for_all_users': settings_obj.enforce_2fa_for_all_users,
            'default_2fa_method': settings_obj.default_2fa_method,
            'code_expiration_seconds': settings_obj.code_expiration_seconds,
            'max_failed_attempts': settings_obj.max_failed_attempts,
            'temporary_token_lifetime_minutes': settings_obj.temporary_token_lifetime_minutes,
        }
        json_config = json.dumps(config_dict, indent=2)
        self.message_user(
            request,
            f"Current 2FA Configuration:\n{json_config}",
            level=messages.SUCCESS
        )
    preview_config_as_json.short_description = "Preview current 2FA configuration"

    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of singleton settings."""
        return False


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom admin interface for User model."""

    # Fields to display in the list view
    list_display = (
        'username',
        'email',
        'first_name',
        'last_name',
        'phone_number',
        'is_2fa_enabled',
        'is_staff',
        'is_active',
        'created_at',
    )

    # Fields to filter by in the list view
    list_filter = (
        'is_staff',
        'is_active',
        'is_superuser',
        'is_2fa_enabled',
        'created_at',
    )

    # Fields to search in the admin
    search_fields = (
        'username',
        'email',
        'first_name',
        'last_name',
        'phone_number',
    )

    # Fields to order by
    ordering = ('-created_at',)

    # Readonly fields
    readonly_fields = ('created_at', 'updated_at', 'last_login', 'date_joined', 'twofa_setup_date', 'last_2fa_verification')

    # Fieldsets for the edit/add form
    fieldsets = (
        (None, {
            'fields': ('username', 'password')
        }),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email', 'phone_number')
        }),
        ('OAuth info', {
            'fields': ('google_id', 'profile_picture_url', 'email_verified')
        }),
        ('Two-Factor Authentication', {
            'fields': (
                'is_2fa_enabled',
                'preferred_2fa_method',
                'phone_number_verified',
                'twofa_setup_date',
                'last_2fa_verification'
            )
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ('Important dates', {
            'fields': ('last_login', 'date_joined', 'created_at', 'updated_at')
        }),
    )

    # Fieldsets for adding a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'phone_number'),
        }),
    )


@admin.register(TwoFactorCode)
class TwoFactorCodeAdmin(admin.ModelAdmin):
    """Admin interface for TwoFactorCode model."""

    list_display = (
        'user',
        'code',
        'verification_type',
        'created_at',
        'expires_at',
        'is_used',
        'failed_attempts',
        'is_valid_status',
    )

    list_filter = (
        'is_used',
        'verification_type',
        'created_at',
        'expires_at',
    )

    search_fields = (
        'user__username',
        'user__email',
        'code',
    )

    readonly_fields = (
        'user',
        'code',
        'created_at',
        'expires_at',
        'is_used',
        'failed_attempts',
        'verification_type',
    )

    ordering = ('-created_at',)

    def is_valid_status(self, obj):
        """Display whether code is currently valid."""
        return obj.is_valid()
    is_valid_status.short_description = 'Valid'
    is_valid_status.boolean = True

    def has_add_permission(self, request):
        """Disable manual creation of codes through admin."""
        return False

    def has_change_permission(self, request, obj=None):
        """Disable editing of codes through admin."""
        return False
