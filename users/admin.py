"""
Admin interface configuration for User model.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model

User = get_user_model()


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
        'is_staff',
        'is_active',
        'created_at',
    )

    # Fields to filter by in the list view
    list_filter = (
        'is_staff',
        'is_active',
        'is_superuser',
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
    readonly_fields = ('created_at', 'updated_at', 'last_login', 'date_joined')

    # Fieldsets for the edit/add form
    fieldsets = (
        (None, {
            'fields': ('username', 'password')
        }),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email', 'phone_number')
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
