from django.conf import settings
from rest_framework.permissions import BasePermission
from users.enums import UserRole


class IsStaffRolePermission(BasePermission):
    """
    Permission to check if the user has a staff role (super admin, admin, clinic admin, clinic staff).
    """

    def has_permission(self, request, view):
        return request.user.role in [
            UserRole.SUPER_ADMIN,
            UserRole.ADMIN,
            UserRole.CLINIC_ADMIN,
            UserRole.CLINIC_STAFF,
        ]


class IsAdminRolePermission(BasePermission):
    """
    Permission to check if the user has a admin role (super admin, admin).
    """

    def has_permission(self, request, view):
        return request.user.role in [
            UserRole.SUPER_ADMIN,
            UserRole.ADMIN,
        ]


class CustomTokenPermission(BasePermission):
    def has_permission(self, request, view):
        token = request.headers.get("X-Custom-Token")
        return token == settings.CUSTOM_TOKEN
