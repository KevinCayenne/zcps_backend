from .models import ActionLog
from .serializers import ActionLogSerializer
from rest_framework import viewsets, filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated
from .filters import ActionLogFilter
from users.permissions import IsStaffRolePermission
from config.paginator import StandardResultsSetPagination


class ActionLogsViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing action logs.

    Only allows read operations (list and retrieve).
    Requires staff role permission.
    """

    queryset = ActionLog.objects.all().order_by("-timestamp")
    serializer_class = ActionLogSerializer
    permission_classes = [IsAuthenticated, IsStaffRolePermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]

    # Use the custom filterset class
    filterset_class = ActionLogFilter
    pagination_class = StandardResultsSetPagination

    # Optional: Add ordering and search
    ordering_fields = ["timestamp", "model_name", "action"]
    ordering = ["-timestamp"]  # Default ordering
    search_fields = ["model_name", "changes", "object_id"]
