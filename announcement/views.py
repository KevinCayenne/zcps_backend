from rest_framework import viewsets, filters, status
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework.response import Response
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter
from users.permissions import IsAdminRolePermission
from users.enums import UserRole
from .models import Announcement
from .serializers import AnnouncementSerializer, ClientAnnouncementSerializer
from .filters import AnnouncementFilterSet
from config.paginator import StandardResultsSetPagination
from django.utils import timezone
from django.conf import settings
from django.utils.html import strip_tags
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)


class IsClientRolePermission(BasePermission):
    """
    Permission to check if the user has CLIENT role (一般會員).
    """

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and hasattr(request.user, "role")
            and request.user.role == UserRole.CLIENT
        )


class AnnouncementViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing announcements.

    Provides CRUD operations for announcements:
    - List: GET /api/announcements/ (with filtering, searching, ordering)
    - Create: POST /api/announcements/
    - Retrieve: GET /api/announcements/{id}/
    - Update: PUT/PATCH /api/announcements/{id}/
    - Delete: DELETE /api/announcements/{id}/
    - Publish: POST /api/announcements/{id}/publish/
    - Unpublish: POST /api/announcements/{id}/unpublish/

    **Permissions:**
    - List and Retrieve: Authenticated users
    - Create, Update, Delete: Admin users only
    """

    queryset = Announcement.objects.all().order_by("-create_time")
    serializer_class = AnnouncementSerializer
    permission_classes = [IsAdminRolePermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    filterset_class = AnnouncementFilterSet
    ordering_fields = [
        "title",
        "is_active",
        "is_send_email",
        "create_time",
        "active_start_time",
        "active_end_time",
    ]
    ordering = ["-create_time"]  # Default ordering: newest first
    search_fields = ["title"]  # Search by title
    pagination_class = StandardResultsSetPagination

    def get_permissions(self):
        """
        Override to require admin permission for write operations.
        """
        if self.action in [
            "create",
            "update",
            "partial_update",
            "destroy",
            "publish",
            "unpublish",
        ]:
            return [IsAuthenticated(), IsAdminRolePermission()]
        return [IsAuthenticated()]

    def get_queryset(self):
        """
        Optionally filter by is_active if requested.
        By default, return all announcements.
        """
        queryset = super().get_queryset()

        # If user is not admin, only show active announcements
        if not (
            self.request.user.is_authenticated
            and hasattr(self.request.user, "role")
            and self.request.user.role in [UserRole.SUPER_ADMIN, UserRole.ADMIN]
        ):
            queryset = queryset.filter(is_active=True)

        return queryset

    @extend_schema(
        tags=["Announcements"],
        summary="Publish announcement",
        description="""
        發布公告（設置 is_active=True）。

        只有管理員可以執行此操作。
        """,
        responses={
            200: OpenApiResponse(description="公告已發布"),
            403: OpenApiResponse(description="權限不足"),
            404: OpenApiResponse(description="公告不存在"),
        },
    )
    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        """
        Publish an announcement (set is_active=True).
        如果 is_send_email=True 且尚未發送過 email，則發送 email 給所有會員。
        同一則公告僅可發送一次 email。
        """
        announcement = self.get_object()
        announcement.is_active = True
        announcement.active_end_time = None
        announcement.active_start_time = timezone.now()
        announcement.active_member.add(request.user)

        # 如果設置了發送 email 且尚未發送過，則發送 email
        email_sent = False
        if announcement.is_send_email and not announcement.email_sent_at:
            # 檢查是否已發送過 email（通過 email_sent_at 欄位）
            try:
                self._send_announcement_email(announcement)
                # 標記已發送 email
                announcement.email_sent_at = timezone.now()
                email_sent = True
                logger.info(
                    "Announcement email sent successfully for announcement %s",
                    announcement.id,
                )
            except Exception as e:
                logger.error(
                    "Failed to send announcement email for announcement %s: %s",
                    announcement.id,
                    str(e),
                )
                # 即使發送失敗，也繼續發布公告
        elif announcement.is_send_email and announcement.email_sent_at:
            logger.info(
                "Announcement %s email already sent at %s, skipping email send",
                announcement.id,
                announcement.email_sent_at,
            )

        announcement.save()

        response_data = {"message": "公告已發布"}
        if email_sent:
            response_data["email_sent"] = True
            response_data["email_message"] = "Email 已發送給所有會員"
        elif announcement.is_send_email and announcement.email_sent_at:
            response_data["email_sent"] = False
            response_data["email_message"] = "Email 已發送過，不會重複發送"
        elif announcement.is_send_email:
            response_data["email_sent"] = False
            response_data["email_message"] = "Email 發送失敗"

        return Response(response_data, status=status.HTTP_200_OK)

    def _send_announcement_email(self, announcement):
        """
        發送公告 email 給所有會員

        Args:
            announcement: Announcement 實例

        Raises:
            Exception: 如果發送失敗
        """
        # 獲取所有會員（CLIENT 角色的用戶）
        from users.models import User

        clients = User.objects.filter(
            role=UserRole.CLIENT, is_active=True, email__isnull=False
        ).exclude(email="")

        if not clients.exists():
            logger.warning(
                "No active clients found to send announcement email for announcement %s",
                announcement.id,
            )
            return

        # 構建公告列表連結（後台登入頁面）
        frontend_url = getattr(settings, "CLIENT_FRONTEND_URL", "http://localhost:3000")
        announcements_url = f"{frontend_url}/announcements"  # 假設公告列表頁面路徑
        site_name = getattr(settings, "SITE_NAME", "系統")

        # 構建 email 內容
        subject = f"{site_name} - 新公告：{announcement.title}"

        header_styles = (
            "color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;"
        )
        highlight_styles = (
            "background-color: #f8f9fa; padding: 15px; border-left: 4px solid"
            " #3498db; margin: 20px 0;"
        )
        button_styles = (
            "background-color: #3498db; color: white; padding: 12px 30px;"
            " text-decoration: none; border-radius: 5px; display: inline-block;"
            " font-weight: bold;"
        )

        # 使用 HTML 模板
        html_message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="{header_styles}">新公告通知</h2>
                <p>親愛的會員：</p>
                <p>我們發布了一則新公告：</p>
                <div style="{highlight_styles}">
                    <h3 style="margin-top: 0; color: #2c3e50;">{announcement.title}</h3>
                </div>
                <p>請點擊以下連結查看完整公告內容：</p>
                <p style="text-align: center; margin: 30px 0;">
                    <a href="{announcements_url}" style="{button_styles}">
                        查看公告列表
                    </a>
                </p>
                <p>或複製以下連結到瀏覽器：</p>
                <p style="word-break: break-all; color: #7f8c8d;">
                    <a href="{announcements_url}" style="color: #3498db;">
                        {announcements_url}
                    </a>
                </p>
                <hr style="border: none; border-top: 1px solid #ecf0f1; margin: 30px 0;">
                <p style="color: #95a5a6; font-size: 12px; margin: 0;">
                    此為系統自動發送，請勿回覆此郵件。
                </p>
            </div>
        </body>
        </html>
        """

        plain_message = strip_tags(html_message)
        plain_message = f"""新公告通知

            親愛的會員：

            我們發布了一則新公告：{announcement.title}

            請點擊以下連結查看完整公告內容：
            {announcements_url}

            此為系統自動發送，請勿回覆此郵件。
        """

        # 獲取所有會員的 email 列表
        recipient_list = list(clients.values_list("email", flat=True))

        if not recipient_list:
            logger.warning("No valid email addresses found for clients")
            return

        # 分批發送郵件，每批最多50個收件人，以保護個資並避免性能問題
        # 每批單獨發送，這樣每個收件人只能看到同一批的其他收件人（最多49個）
        # 如果完全不想讓收件人看到其他人，可以將 BATCH_SIZE 設為 1
        from django.core.mail import EmailMultiAlternatives, get_connection

        BATCH_SIZE = 50  # 每批最多50個收件人，可以根據需要調整

        success_count = 0
        failed_count = 0
        total_batches = (len(recipient_list) + BATCH_SIZE - 1) // BATCH_SIZE

        # 重用郵件連接以提高效率
        connection = get_connection()

        for batch_num in range(0, len(recipient_list), BATCH_SIZE):
            batch_recipients = recipient_list[batch_num : batch_num + BATCH_SIZE]
            batch_num_display = (batch_num // BATCH_SIZE) + 1

            try:
                # 為每批收件人創建一封郵件
                email_msg = EmailMultiAlternatives(
                    subject=subject,
                    body=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[],  # 使用空列表，避免在 To 欄位顯示收件人
                    bcc=batch_recipients,  # 每批收件人使用密件副本
                    connection=connection,  # 重用連接
                )
                email_msg.attach_alternative(html_message, "text/html")
                email_msg.send(fail_silently=False)
                success_count += len(batch_recipients)
                logger.debug(
                    f"Announcement email batch {batch_num_display}/{total_batches} sent successfully "
                    f"to {len(batch_recipients)} recipients"
                )
            except Exception as e:
                logger.error(
                    f"Failed to send announcement email batch {batch_num_display}/{total_batches}: {e}",
                    exc_info=True,
                )
                failed_count += len(batch_recipients)

        # 關閉連接
        connection.close()

        logger.info(
            f"Announcement email sent successfully to {success_count} clients "
            f"(failed: {failed_count}, batches: {total_batches}) "
            f"for announcement {announcement.id} (title: {announcement.title})"
        )

    @extend_schema(
        tags=["Announcements"],
        summary="Unpublish announcement",
        description="""
        取消發布公告（設置 is_active=False）。

        只有管理員可以執行此操作。
        """,
        responses={
            200: OpenApiResponse(description="公告已取消發布"),
            403: OpenApiResponse(description="權限不足"),
            404: OpenApiResponse(description="公告不存在"),
        },
    )
    @action(detail=True, methods=["post"])
    def unpublish(self, request, pk=None):
        """
        Unpublish an announcement (set is_active=False).
        """
        announcement = self.get_object()
        announcement.active_start_time = None
        announcement.active_end_time = None
        announcement.active_member.remove(request.user)
        announcement.is_active = False
        announcement.save()
        return Response({"message": "公告已取消發布"}, status=status.HTTP_200_OK)

    @extend_schema(
        tags=["Announcements"],
        summary="List announcements",
        description="""
        獲取公告列表。

        **查詢參數：**
        - `is_active`: 是否發布（可選，true/false）
        - `is_send_email`: 是否發送電子郵件通知（可選，true/false）
        - `search`: 搜尋關鍵字（可選，會搜尋標題）
        - `ordering`: 排序欄位（可選，如：title, -create_time, is_active）
        - `create_time__gte`: 創建時間起始（可選）
        - `create_time__lte`: 創建時間結束（可選）
        - `active_start_time__gte`: 生效時間起始（可選）
        - `active_start_time__lte`: 生效時間結束（可選）
        - `active_end_time__gte`: 失效時間起始（可選）
        - `active_end_time__lte`: 失效時間結束（可選）
        - `active_member__gte`: 發布人起始（可選）
        - `active_member__lte`: 發布人結束（可選）

        **注意：**
        - 非管理員用戶只能看到已發布的公告（is_active=True）
        """,
        parameters=[
            OpenApiParameter(
                name="is_active",
                type=bool,
                location=OpenApiParameter.QUERY,
                required=False,
                description="是否發布（true/false）",
            ),
            OpenApiParameter(
                name="search",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="搜尋關鍵字（會搜尋標題）",
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        """
        List all announcements.
        """
        return super().list(request, *args, **kwargs)


class ClientAnnouncementViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for client users to view published announcements.

    Provides read-only operations for client users:
    - List: GET /api/client-announcements/ (only published announcements)
    - Retrieve: GET /api/client-announcements/{id}/ (only published announcements)

    **Permissions:**
    - Only CLIENT role users can access
    - Only shows announcements where is_active=True
    - Only shows announcements within valid time range (active_start_time and active_end_time)
    """

    queryset = Announcement.objects.all().order_by("-create_time")
    serializer_class = ClientAnnouncementSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    ordering_fields = [
        "title",
        "create_time",
        "active_start_time",
    ]
    ordering = ["-create_time"]  # Default ordering: newest first
    search_fields = ["title"]  # Search by title
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """
        只返回已發布且在有效期內的公告。
        """
        now = timezone.now()
        queryset = super().get_queryset()

        # 只返回已發布的公告
        queryset = queryset.filter(is_active=True)

        # 檢查生效時間：如果設置了 active_start_time，必須小於等於現在
        queryset = queryset.filter(
            Q(active_start_time__isnull=True) | Q(active_start_time__lte=now)
        )

        # 檢查失效時間：如果設置了 active_end_time，必須大於等於現在
        queryset = queryset.filter(
            Q(active_end_time__isnull=True) | Q(active_end_time__gte=now)
        )

        return queryset

    @extend_schema(
        tags=["Client Announcements"],
        summary="List published announcements for clients",
        description="""
        獲取已發布的公告列表（僅供一般會員使用）。

        **權限要求：**
        - 只有 CLIENT 角色的用戶可以訪問

        **返回內容：**
        - 只返回 is_active=True 的公告
        - 只返回在有效期內的公告（檢查 active_start_time 和 active_end_time）

        **查詢參數：**
        - `search`: 搜尋關鍵字（可選，會搜尋標題）
        - `ordering`: 排序欄位（可選，如：title, -create_time, active_start_time）
        - `create_time__gte`: 創建時間起始（可選）
        - `create_time__lte`: 創建時間結束（可選）
        - `active_start_time__gte`: 生效時間起始（可選）
        - `active_start_time__lte`: 生效時間結束（可選）
        - `active_end_time__gte`: 失效時間起始（可選）
        - `active_end_time__lte`: 失效時間結束（可選）
        """,
        parameters=[
            OpenApiParameter(
                name="search",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="搜尋關鍵字（會搜尋標題）",
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        """
        獲取已發布的公告列表（僅供一般會員使用）。
        """
        return super().list(request, *args, **kwargs)

    @extend_schema(
        tags=["Client Announcements"],
        summary="Retrieve published announcement for clients",
        description="""
        獲取已發布的公告詳細資訊（僅供一般會員使用）。

        **權限要求：**
        - 只有 CLIENT 角色的用戶可以訪問

        **返回內容：**
        - 只返回 is_active=True 的公告
        - 只返回在有效期內的公告（檢查 active_start_time 和 active_end_time）
        - 如果公告不存在或未發布，返回 404
        """,
    )
    def retrieve(self, request, *args, **kwargs):
        """
        獲取已發布的公告詳細資訊（僅供一般會員使用）。
        """
        return super().retrieve(request, *args, **kwargs)
