from rest_framework import serializers
from .models import ActionLog
from django.contrib.auth import get_user_model

User = get_user_model()


class ActionLogUserSerializer(serializers.ModelSerializer):
    """簡化的 User serializer 用於 ActionLog"""

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name")
        read_only_fields = ("id", "username", "email", "first_name", "last_name")


class ActionLogSerializer(serializers.ModelSerializer):
    user = ActionLogUserSerializer(read_only=True)

    class Meta:
        model = ActionLog
        fields = (
            "id",
            "user",
            "model_name",
            "action",
            "timestamp",
            "object_id",
            "changes",
        )
        read_only_fields = (
            "id",
            "user",
            "model_name",
            "action",
            "timestamp",
            "object_id",
            "changes",
        )
