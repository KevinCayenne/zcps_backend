from croniter import croniter
from rest_framework import serializers
from django.contrib.auth import get_user_model
from users.serializers import UserSerializer
from .models import NotificationTask

User = get_user_model()


class NotificationTaskSerializer(serializers.ModelSerializer):
    targets_details = UserSerializer(source="targets", many=True, read_only=True)
    target_ids = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source="targets",
        many=True,
        write_only=True,
        required=False,
    )

    class Meta:
        model = NotificationTask
        fields = (
            "id",
            "name",
            "enable",
            "period",
            "start_time",
            "end_time",
            "contents",
            "target_ids",
            "targets_details",
            "create_time",
            "update_time",
            "create_user",
        )
        read_only_fields = ("id", "create_time", "update_time", "create_user")

    def validate_period(self, value):
        if not croniter.is_valid(value):
            raise serializers.ValidationError("Invalid cron expression.")
        return value

    def create(self, validated_data):
        user = self.context["request"].user
        validated_data["create_user"] = user
        return super().create(validated_data)
