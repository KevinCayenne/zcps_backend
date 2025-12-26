"""
Filter sets for announcement models.

Provides custom filtering capabilities for Announcement model.
"""

import django_filters
from .models import Announcement


class AnnouncementFilterSet(django_filters.FilterSet):
    """
    Filter set for Announcement model.

    Supports filtering by:
    - is_active: Filter by active status (exact match)
    - is_send_email: Filter by email notification status (exact match)
    - create_time: Date range filtering
    - active_start_time: Date range filtering
    - active_end_time: Date range filtering
    - active_member: Filter by user ID (ManyToMany relationship)
    """

    # Boolean fields - exact match
    is_active = django_filters.BooleanFilter()
    is_send_email = django_filters.BooleanFilter()

    # ManyToMany field - filter by user ID
    active_member = django_filters.NumberFilter(
        method="filter_by_active_member",
        help_text="用戶 ID（用於篩選包含該用戶的公告）",
    )

    # Date fields - support range filtering
    create_time = django_filters.DateTimeFilter()
    create_time__gte = django_filters.DateTimeFilter(
        field_name="create_time", lookup_expr="gte"
    )
    create_time__lte = django_filters.DateTimeFilter(
        field_name="create_time", lookup_expr="lte"
    )

    active_start_time = django_filters.DateTimeFilter()
    active_start_time__gte = django_filters.DateTimeFilter(
        field_name="active_start_time", lookup_expr="gte"
    )
    active_start_time__lte = django_filters.DateTimeFilter(
        field_name="active_start_time", lookup_expr="lte"
    )

    active_end_time = django_filters.DateTimeFilter()
    active_end_time__gte = django_filters.DateTimeFilter(
        field_name="active_end_time", lookup_expr="gte"
    )
    active_end_time__lte = django_filters.DateTimeFilter(
        field_name="active_end_time", lookup_expr="lte"
    )

    def filter_by_active_member(self, queryset, name, value):
        """
        通過用戶 ID 篩選公告

        查找所有包含該用戶在 active_member 中的公告
        """
        try:
            user_id = int(value)
            # 使用 ManyToMany 關係的過濾方式
            return queryset.filter(active_member__id=user_id).distinct()
        except (ValueError, TypeError):
            # 如果 user_id 不是有效的整數，返回空查詢集
            return queryset.none()

    class Meta:
        model = Announcement
        fields = [
            "is_active",
            "is_send_email",
            "create_time",
            "active_start_time",
            "active_end_time",
            "active_member",
        ]
