"""
Filter sets for user models.

Provides custom filtering capabilities for User model with support for
case-insensitive partial matching on text fields.
"""
import django_filters
from .models import User

# 動態導入以避免循環導入
try:
    from clinic.models import ClinicUserPermission, Clinic
except ImportError:
    ClinicUserPermission = None
    Clinic = None


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
    
    # 診所篩選 - 通過 ClinicUserPermission 查找用戶
    clinic = django_filters.NumberFilter(method='filter_by_clinic', help_text='診所 ID（用於篩選擁有該診所權限的用戶）')
    clinic_id = django_filters.NumberFilter(method='filter_by_clinic', help_text='診所 ID（用於篩選擁有該診所權限的用戶）')
    
    def filter_by_clinic(self, queryset, name, value):
        """
        通過診所 ID 篩選用戶
        
        查找所有擁有該診所權限的用戶
        """
        if ClinicUserPermission is None or Clinic is None:
            return queryset
        
        try:
            clinic_id = int(value)
            # 驗證診所是否存在
            if not Clinic.objects.filter(id=clinic_id).exists():
                return queryset.none()
            
            # 找到所有擁有該診所權限的用戶 ID
            user_ids = ClinicUserPermission.objects.filter(
                clinic_id=clinic_id
            ).values_list('user_id', flat=True).distinct()
            
            # 篩選出這些用戶
            return queryset.filter(id__in=user_ids)
        except (ValueError, TypeError):
            # 如果 clinic_id 不是有效的整數，返回空查詢集
            return queryset.none()
    
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
            'clinic',
            'clinic_id',
        ]

