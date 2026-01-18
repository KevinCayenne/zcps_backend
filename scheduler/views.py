from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import NotificationTask
from .serializers import NotificationTaskSerializer
from .executor import TaskExecutor
from users.permissions import CustomTokenPermission


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
