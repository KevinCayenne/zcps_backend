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