"""
Filter sets for clinic models.

Provides custom filtering capabilities for Clinic model with support for
case-insensitive partial matching on text fields.
"""
import django_filters
from .models import Clinic, CertificateApplication
from .enums import CertificateApplicationStatus


class ClinicFilterSet(django_filters.FilterSet):
    """
    Filter set for Clinic model.
    
    Supports case-insensitive partial matching (icontains) for text fields:
    - name (診所名稱)
    - number (編號)
    - address (地址)
    - phone (電話)
    - email (電子郵件)
    - website (網站)
    
    Date fields support range filtering:
    - create_time (建立時間)
    - update_time (更新時間)
    """
    
    # Text fields with icontains search
    name = django_filters.CharFilter(lookup_expr='icontains', help_text='診所名稱（部分匹配，不區分大小寫）')
    number = django_filters.CharFilter(lookup_expr='icontains', help_text='診所編號（部分匹配，不區分大小寫）')
    address = django_filters.CharFilter(lookup_expr='icontains', help_text='地址（部分匹配，不區分大小寫）')
    phone = django_filters.CharFilter(lookup_expr='icontains', help_text='電話（部分匹配，不區分大小寫）')
    email = django_filters.CharFilter(lookup_expr='icontains', help_text='電子郵件（部分匹配，不區分大小寫）')
    website = django_filters.CharFilter(lookup_expr='icontains', help_text='網站（部分匹配，不區分大小寫）')
    
    # Date fields - support range filtering
    create_time = django_filters.DateTimeFilter()
    create_time__gte = django_filters.DateTimeFilter(field_name='create_time', lookup_expr='gte', help_text='建立時間（大於等於）')
    create_time__lte = django_filters.DateTimeFilter(field_name='create_time', lookup_expr='lte', help_text='建立時間（小於等於）')
    
    update_time = django_filters.DateTimeFilter()
    update_time__gte = django_filters.DateTimeFilter(field_name='update_time', lookup_expr='gte', help_text='更新時間（大於等於）')
    update_time__lte = django_filters.DateTimeFilter(field_name='update_time', lookup_expr='lte', help_text='更新時間（小於等於）')
    
    class Meta:
        model = Clinic
        fields = [
            'name',
            'number',
            'address',
            'phone',
            'email',
            'website',
            'create_time',
            'update_time',
        ]


class CertificateApplicationFilterSet(django_filters.FilterSet):
    """
    Filter set for CertificateApplication model.
    
    Supports filtering by:
    - user (用戶 ID)
    - clinic (診所 ID)
    - consultation_clinic (諮詢診所 ID)
    - status (狀態)
    - surgeon_name (手術醫師姓名，部分匹配)
    - consultant_name (諮詢師姓名，部分匹配)
    - Date range filtering for create_time, update_time, verified_at, issued_at
    """
    
    # Foreign key filters
    user = django_filters.NumberFilter(help_text='用戶 ID')
    clinic = django_filters.NumberFilter(help_text='診所 ID')
    consultation_clinic = django_filters.NumberFilter(help_text='諮詢診所 ID')
    
    # Status filter
    status = django_filters.ChoiceFilter(
        choices=CertificateApplicationStatus.CHOICES,
        help_text='申請狀態'
    )
    
    # Text fields with icontains search
    surgeon_name = django_filters.CharFilter(lookup_expr='icontains', help_text='手術醫師姓名（部分匹配，不區分大小寫）')
    consultant_name = django_filters.CharFilter(lookup_expr='icontains', help_text='諮詢師姓名（部分匹配，不區分大小寫）')
    
    # Date fields - support range filtering
    create_time = django_filters.DateTimeFilter()
    create_time__gte = django_filters.DateTimeFilter(field_name='create_time', lookup_expr='gte', help_text='建立時間（大於等於）')
    create_time__lte = django_filters.DateTimeFilter(field_name='create_time', lookup_expr='lte', help_text='建立時間（小於等於）')
    
    update_time = django_filters.DateTimeFilter()
    update_time__gte = django_filters.DateTimeFilter(field_name='update_time', lookup_expr='gte', help_text='更新時間（大於等於）')
    update_time__lte = django_filters.DateTimeFilter(field_name='update_time', lookup_expr='lte', help_text='更新時間（小於等於）')
    
    verified_at = django_filters.DateTimeFilter()
    verified_at__gte = django_filters.DateTimeFilter(field_name='verified_at', lookup_expr='gte', help_text='驗證時間（大於等於）')
    verified_at__lte = django_filters.DateTimeFilter(field_name='verified_at', lookup_expr='lte', help_text='驗證時間（小於等於）')
    
    issued_at = django_filters.DateTimeFilter()
    issued_at__gte = django_filters.DateTimeFilter(field_name='issued_at', lookup_expr='gte', help_text='發證時間（大於等於）')
    issued_at__lte = django_filters.DateTimeFilter(field_name='issued_at', lookup_expr='lte', help_text='發證時間（小於等於）')
    
    class Meta:
        model = CertificateApplication
        fields = [
            'user',
            'clinic',
            'consultation_clinic',
            'status',
            'surgeon_name',
            'consultant_name',
            'create_time',
            'update_time',
            'verified_at',
            'issued_at',
        ]

