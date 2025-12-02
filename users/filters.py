"""
Filter sets for user models.

Provides custom filtering capabilities for User model with support for
case-insensitive partial matching on text fields.
"""
import django_filters
from .models import User


class UserFilterSet(django_filters.FilterSet):
    """
    Filter set for User model.
    
    Supports case-insensitive partial matching (icontains) for text fields:
    - first_name
    - last_name
    - username
    - email
    
    Other fields use default filtering:
    - is_active (exact match)
    - role (exact match)
    - last_login (date range)
    - created_at (date range)
    - updated_at (date range)
    """
    
    # Text fields with icontains search
    first_name = django_filters.CharFilter(lookup_expr='icontains')
    last_name = django_filters.CharFilter(lookup_expr='icontains')
    username = django_filters.CharFilter(lookup_expr='icontains')
    email = django_filters.CharFilter(lookup_expr='icontains')
    
    # Boolean field - exact match
    is_active = django_filters.BooleanFilter()
    
    # Choice field - exact match
    role = django_filters.CharFilter()
    
    # Date fields - support range filtering
    last_login = django_filters.DateTimeFilter()
    last_login__gte = django_filters.DateTimeFilter(field_name='last_login', lookup_expr='gte')
    last_login__lte = django_filters.DateTimeFilter(field_name='last_login', lookup_expr='lte')
    
    created_at = django_filters.DateTimeFilter()
    created_at__gte = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_at__lte = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    updated_at = django_filters.DateTimeFilter()
    updated_at__gte = django_filters.DateTimeFilter(field_name='updated_at', lookup_expr='gte')
    updated_at__lte = django_filters.DateTimeFilter(field_name='updated_at', lookup_expr='lte')
    
    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'is_active',
            'username',
            'last_login',
            'email',
            'role',
            'created_at',
            'updated_at',
        ]

