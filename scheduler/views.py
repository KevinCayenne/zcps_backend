import calendar

from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import NotificationTask
from .serializers import NotificationTaskSerializer
from .executor import TaskExecutor
from users.permissions import CustomTokenPermission
from users.models import User
from users.sns_sender.utils import send_sms


class TaskViewSet(viewsets.ModelViewSet):
    queryset = NotificationTask.objects.all()
    serializer_class = NotificationTaskSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return NotificationTask.objects.all().order_by("-create_time")


class ExecutorView(APIView):
    permission_classes = [CustomTokenPermission]

    def post(self, request, *args, **kwargs):
        executor = TaskExecutor()
        results = executor.execute()
        return Response(results, status=status.HTTP_200_OK)


class MonthlyRegistrationSmsView(APIView):
    permission_classes = [CustomTokenPermission]

    def _subtract_one_month(self, base_date):
        year = base_date.year
        month = base_date.month - 1
        if month == 0:
            month = 12
            year -= 1
        day = min(base_date.day, calendar.monthrange(year, month)[1])
        return base_date.replace(year=year, month=month, day=day)

    def post(self, request, *args, **kwargs):
        today = timezone.localdate()
        target_date = self._subtract_one_month(today)

        users = User.objects.filter(date_joined__date=target_date).order_by("id")

        sms_template = "親愛的{name}，感謝您加入我們，今天已滿一個月，祝您使用愉快！"

        sent = 0
        skipped_no_phone = 0
        failed = []

        for user in users:
            phone_number = getattr(user, "phone_number", None)
            if not phone_number:
                skipped_no_phone += 1
                continue

            display_name = user.first_name or user.username or "會員"
            message = sms_template.format(name=display_name)
            result = send_sms(phone_number, message)

            if result.get("status") == "success":
                sent += 1
            else:
                failed.append(
                    {
                        "user_id": user.id,
                        "message": result.get("message", "Unknown error"),
                    }
                )

        return Response(
            {
                "status": "success",
                "target_date": str(target_date),
                "total_targets": users.count(),
                "sent": sent,
                "skipped_no_phone": skipped_no_phone,
                "failed": failed,
            },
            status=status.HTTP_200_OK,
        )
