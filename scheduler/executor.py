import logging
from croniter import croniter
from django.utils import timezone
from django.db import models
from .models import NotificationTask

logger = logging.getLogger(__name__)


class TaskExecutor:
    def execute(self):
        now = timezone.localtime()
        # Round to minute? Cron usually works on minute boundaries.

        # 1. Filter enable tasks active in time range
        tasks = NotificationTask.objects.filter(
            enable=True, start_time__lte=now
        ).filter(models.Q(end_time__gte=now) | models.Q(end_time__isnull=True))
        logger.info(f"Found {tasks.count()} tasks to execute")

        executed_tasks = []

        for task in tasks:
            if self.should_run(task, now):
                logger.info(f"Running task: {task.name}")
                self.run_task(task)
                executed_tasks.append(task.id)

        return {"status": "success", "executed_task_ids": executed_tasks}

    def should_run(self, task, now):
        try:
            # Check if current time matches cron period
            # Allowing 1 minute tolerance
            croniter(task.period, now)
            # croniter.match(now) might work if we are exact.
            # simpler approach: get previous schedule time and see if it is within this execution window (~5 mins)
            # So we just check croniter.match(now) with minute precision.
            return croniter.match(task.period, now)
        except Exception as e:
            logger.error(f"Error checking cron for task {task.id}: {e}")
            return False

    def run_task(self, task):
        # Optimized fetching
        targets = task.targets.all()
        if not targets.exists() and task.roles:
            from django.contrib.auth import get_user_model

            User = get_user_model()
            targets = User.objects.filter(role__in=task.roles)

        for content in task.contents:
            channel = content.get("channel")
            body_template = content.get("body", "")
            title_template = content.get("title", "")

            if channel == "sms":
                # Bulk SMS logic
                # For each user, format and send
                # To be efficient, we should maybe group sends if the provider supports it,
                # but customization ({username}) prevents bulk send with same body.
                for user in targets:
                    context = self.get_context(user)
                    try:
                        message = body_template.format(**context)
                        self.send_sms(user, message)
                    except Exception as e:
                        logger.error(f"Failed to send SMS to {user}: {e}")

            elif channel == "email":
                for user in targets:
                    context = self.get_context(user)
                    try:
                        title = title_template.format(**context)
                        body = body_template.format(**context)
                        self.send_email(user, title, body)
                    except Exception as e:
                        logger.error(f"Failed to send Email to {user}: {e}")

    def get_context(self, user):
        return {
            "username": user.username,
        }

    def send_sms(self, user, message):
        from users.sns_sender.utils import send_sms

        # Ensure user has a phone number
        phone_number = getattr(user, "phone_number", None)

        if phone_number:
            try:
                result = send_sms(phone_number, message)
                if result.get("status") == "success":
                    logger.info(
                        f"[SMS] Sent to {user.username} ({phone_number}): {message}"
                    )
                else:
                    logger.error(
                        f"[SMS] Failed to {user.username}: {result.get('message')}"
                    )
            except Exception as e:
                logger.error(f"[SMS] Exception for {user.username}: {e}")
        else:
            logger.warning(f"[SMS] No phone number for {user.username}")

    def send_email(self, user, title, body):
        # Implementation of sending Email like DJOSER
        from django.core.mail import send_mail
        from django.conf import settings

        # 診斷：檢查 SMTP 認證資訊
        if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
            logger.error(
                f"SMTP 認證資訊未設定！"
                f"EMAIL_HOST_USER: {'已設定' if settings.EMAIL_HOST_USER else '未設定'}, "
                f"EMAIL_HOST_PASSWORD: {'已設定' if settings.EMAIL_HOST_PASSWORD else '未設定'}"
            )
            # Log error but don't crash the whole executor loop, just this task
            logger.error(
                "請確認環境變數 SES_SMTP_USER 和 SES_SMTP_PASSWORD 已正確載入。"
            )
            return

        if user.email:
            logger.info(
                f"發送通知郵件至: {user.email}, 寄件者: {settings.DEFAULT_FROM_EMAIL}"
            )
            try:
                send_mail(
                    title,
                    body,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                logger.info(f"[Email] To {user.username}: {title}")
            except Exception as e:
                logger.error(f"[Email] Failed to send to {user.username}: {e}")
