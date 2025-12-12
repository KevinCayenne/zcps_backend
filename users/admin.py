"""
Admin interface configuration for User model.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model

from users.models import TwoFactorCode

User = get_user_model()

admin.site.site_header = "DJBoilerplate 後台"
admin.site.site_title = "DJBoilerplate 後台"
admin.site.index_title = "DJBoilerplate"

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
        'role',
        'is_2fa_enabled',
        'is_staff',
        'is_active',
        'created_at',
    )

    # Fields to filter by in the list view
    list_filter = (
        'role',
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
            'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
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
