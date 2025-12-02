# filters.py

from django_filters import rest_framework as filters
from .models import ActionLog
from django.db.models import Q


class ActionLogFilter(filters.FilterSet):
    # Define the filters
    model_name = filters.CharFilter(method="filter_by_model_name_object_id")

    class Meta:
        model = ActionLog
        fields = ["user", "action", "model_name", "timestamp", "object_id", "changes"]

    def filter_by_model_name_object_id(self, queryset, name, value):
        pairs = value.split(",")
        conditions = Q()

        for pair in pairs:
            try:
                model_name, object_id = pair.split(":")

                # Handle the special case for 'UserStockPermission'
                if model_name == "UserStockPermission":
                    conditions |= Q(
                        model_name=model_name, changes__icontains=object_id
                    )  # Filter by user__id
                else:
                    conditions |= Q(model_name=model_name, object_id=object_id)

            except ValueError:
                # If the format is invalid, skip this pair
                continue

        return queryset.filter(conditions)
