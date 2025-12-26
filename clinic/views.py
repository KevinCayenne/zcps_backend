"""
Views for Clinic and Certificate Application.
"""

import logging
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.utils.html import strip_tags
from rest_framework import status, serializers, viewsets, filters
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    OpenApiParameter,
    inline_serializer,
)
from users.permissions import IsAdminRolePermission, IsStaffRolePermission
from users.enums import UserRole

from users.models import User
from clinic.models import Clinic, CertificateApplication, Doctor, ClinicUserPermission
from clinic.enums import CertificateApplicationStatus
from clinic.serializers import (
    CertificateApplicationCreateSerializer,
    CertificateApplicationSerializer,
    ClinicSerializer,
    DoctorSerializer,
    ClinicUserPermissionSerializer,
)
from config.paginator import StandardResultsSetPagination
from clinic.filters import ClinicFilterSet, CertificateApplicationFilterSet
from users.certificate_views import (
    get_template,
    issue_certificates_to_new_group,
    issue_certificates_to_existing_group,
    build_certs_data_from_template,
    get_certificate,
    get_pdf_url,
)

logger = logging.getLogger(__name__)


def check_certificate_application_permission(user, application):
    """
    檢查用戶是否有權限訪問指定的證書申請（獨立函數，可在多個類中使用）

    Args:
        user: 當前用戶
        application: CertificateApplication 實例

    Returns:
        tuple: (has_permission: bool, error_message: str or None)
    """
    if not hasattr(user, "role"):
        return False, "用戶沒有角色資訊"

    # 超級管理員和管理員可以訪問所有申請
    if user.role in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        return True, None

    # 診所管理員和診所員工只能訪問與他們有 ClinicUserPermission 關聯的診所相關的申請
    if user.role in [UserRole.CLINIC_ADMIN, UserRole.CLINIC_STAFF]:
        has_permission = ClinicUserPermission.objects.filter(
            user=user, clinic=application.clinic
        ).exists()
        if not has_permission:
            return False, "您沒有權限訪問此診所的證書申請"
        return True, None

    # 普通用戶只能訪問自己的申請
    if user.role == UserRole.CLIENT:
        if application.user != user:
            return False, "您只能訪問自己的證書申請"
        return True, None

    # 其他角色無權限
    return False, "您沒有權限訪問證書申請"


class ClinicViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing clinics.

    Provides CRUD operations for clinics:
    - List: GET /api/clinics/ (with filtering, searching, ordering)
    - Create: POST /api/clinics/
    - Retrieve: GET /api/clinics/{id}/
    - Update: PUT/PATCH /api/clinics/{id}/
    - Delete: DELETE /api/clinics/{id}/
    """

    queryset = Clinic.objects.all().order_by("-create_time")
    serializer_class = ClinicSerializer
    permission_classes = [IsStaffRolePermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    filterset_class = ClinicFilterSet
    ordering_fields = [
        "name",
        "number",
        "address",
        "phone",
        "email",
        "website",
        "create_time",
        "update_time",
    ]
    ordering = ["name"]
    search_fields = ["name", "number", "address", "phone", "email", "website"]
    pagination_class = StandardResultsSetPagination

    def destroy(self, request, *args, **kwargs):
        """
        刪除診所資料。

        如果診所有相關聯的資料（診所用戶權限、醫生、證書申請），則無法刪除。
        """
        instance = self.get_object()

        # 檢查是否有相關聯的資料
        related_data = []

        # 檢查診所用戶權限
        clinic_user_permissions_count = instance.clinic_user_permissions.count()
        if clinic_user_permissions_count > 0:
            related_data.append(f"診所用戶權限 ({clinic_user_permissions_count} 筆)")

        # 檢查診所醫生
        doctors_count = instance.doctors.count()
        if doctors_count > 0:
            related_data.append(f"診所醫生 ({doctors_count} 筆)")

        # 檢查證書申請
        certificate_applications_count = instance.certificate_applications.count()
        if certificate_applications_count > 0:
            related_data.append(f"證書申請 ({certificate_applications_count} 筆)")

        # 如果有相關聯的資料，返回錯誤
        if related_data:
            error_message = f"無法刪除診所資料，因為存在以下相關聯的資料：{', '.join(related_data)}。請先刪除相關資料後再嘗試刪除診所。"
            return Response(
                {"detail": error_message, "related_data": related_data},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 如果沒有相關聯的資料，執行刪除
        return super().destroy(request, *args, **kwargs)


class PublicClinicViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for public access to clinic information (read-only).

    Provides read-only operations for public users:
    - List: GET /api/public-clinics/ (with filtering, searching, ordering)
    - Retrieve: GET /api/public-clinics/{id}/

    **Permissions:**
    - Public access (AllowAny)
    - Read-only operations only (no create, up date, delete)
    """

    queryset = Clinic.objects.all().order_by("-create_time")
    serializer_class = ClinicSerializer
    permission_classes = [AllowAny]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    filterset_class = ClinicFilterSet
    ordering_fields = [
        "name",
        "number",
        "address",
        "phone",
        "email",
        "website",
        "create_time",
        "update_time",
    ]
    ordering = ["name"]
    search_fields = ["name", "number", "address", "phone", "email", "website"]
    pagination_class = StandardResultsSetPagination

    @extend_schema(
        tags=["Public Clinics"],
        summary="List clinics (public)",
        description="""
        獲取診所列表（公開訪問，只讀）。

        **權限要求：**
        - 公開訪問，無需認證

        **查詢參數：**
        - `name`: 診所名稱（可選，部分匹配，不區分大小寫）
        - `number`: 診所編號（可選，部分匹配，不區分大小寫）
        - `address`: 地址（可選，部分匹配，不區分大小寫）
        - `phone`: 電話（可選，部分匹配，不區分大小寫）
        - `email`: 電子郵件（可選，部分匹配，不區分大小寫）
        - `website`: 網站（可選，部分匹配，不區分大小寫）
        - `search`: 搜尋關鍵字（可選，會搜尋名稱、編號、地址、電話、email、網站）
        - `ordering`: 排序欄位（可選，如：name, -create_time, number）
        - `create_time__gte`: 建立時間（大於等於）
        - `create_time__lte`: 建立時間（小於等於）
        - `update_time__gte`: 更新時間（大於等於）
        - `update_time__lte`: 更新時間（小於等於）
        """,
        parameters=[
            OpenApiParameter(
                name="search",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="搜尋關鍵字（會搜尋名稱、編號、地址、電話、email、網站）",
            ),
            OpenApiParameter(
                name="name",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="診所名稱（部分匹配，不區分大小寫）",
            ),
            OpenApiParameter(
                name="number",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="診所編號（部分匹配，不區分大小寫）",
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        """
        獲取診所列表（公開訪問，只讀）。
        """
        return super().list(request, *args, **kwargs)

    @extend_schema(
        tags=["Public Clinics"],
        summary="Retrieve clinic (public)",
        description="""
        獲取診所詳細資訊（公開訪問，只讀）。

        **權限要求：**
        - 公開訪問，無需認證

        **返回內容：**
        - 診所的完整資訊（名稱、編號、地址、電話、email、網站等）
        - 如果診所不存在，返回 404
        """,
    )
    def retrieve(self, request, *args, **kwargs):
        """
        獲取診所詳細資訊（公開訪問，只讀）。
        """
        return super().retrieve(request, *args, **kwargs)


class ClinicUserPermissionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing clinic user permissions.

    Provides CRUD operations for clinic-user permission relationships:
    - List: GET /api/clinic-permissions/ (with optional clinic_id and user_id filters)
    - Create: POST /api/clinic-permissions/
    - Retrieve: GET /api/clinic-permissions/{id}/
    - Update: PUT/PATCH /api/clinic-permissions/{id}/
    - Delete: DELETE /api/clinic-permissions/{id}/
    """

    queryset = (
        ClinicUserPermission.objects.select_related("clinic", "user")
        .all()
        .order_by("-create_time")
    )
    serializer_class = ClinicUserPermissionSerializer
    permission_classes = [IsStaffRolePermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    filterset_fields = ["clinic", "user"]
    ordering_fields = ["create_time", "update_time"]
    ordering = ["-create_time"]
    search_fields = ["clinic__name", "user__username", "user__email"]
    pagination_class = StandardResultsSetPagination

    @extend_schema(
        tags=["Clinic Permissions"],
        summary="List clinic user permissions",
        description="""
        獲取診所用戶權限列表。

        **查詢參數：**
        - `clinic`: 診所 ID（可選，用於篩選特定診所的權限）
        - `user`: 用戶 ID（可選，用於篩選特定用戶的權限）
        - `search`: 搜尋關鍵字（可選，會搜尋診所名稱、用戶名、用戶 email）
        - `ordering`: 排序欄位（可選，如：create_time, -create_time）
        """,
        parameters=[
            OpenApiParameter(
                name="clinic",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description="診所 ID（用於篩選特定診所的權限）",
            ),
            OpenApiParameter(
                name="user",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description="用戶 ID（用於篩選特定用戶的權限）",
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        """獲取診所用戶權限列表"""
        return super().list(request, *args, **kwargs)

    @extend_schema(
        tags=["Clinic Permissions"],
        summary="Create clinic user permission",
        description="""
        創建診所用戶權限關係。

        **必填欄位：**
        - `clinic_id`: 診所 ID
        - `user_id`: 用戶 ID

        **注意事項：**
        - 同一用戶和診所的組合應該是唯一的
        - 如果已存在相同的權限關係，可能會返回錯誤
        """,
        examples=[
            OpenApiExample(
                "Create Permission Request",
                value={"clinic_id": 1, "user_id": 1},
                request_only=True,
            ),
        ],
    )
    def create(self, request, *args, **kwargs):
        """創建診所用戶權限"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # 驗證必填欄位
        if "clinic_id" not in serializer.validated_data:
            return Response(
                {"error": "clinic_id 是必填欄位"}, status=status.HTTP_400_BAD_REQUEST
            )

        if "user_id" not in serializer.validated_data:
            return Response(
                {"error": "user_id 是必填欄位"}, status=status.HTTP_400_BAD_REQUEST
            )

        # 獲取診所和用戶（已在 serializer 中驗證）
        clinic_id = serializer.validated_data.pop("clinic_id")
        clinic = Clinic.objects.get(id=clinic_id)

        user_id = serializer.validated_data.pop("user_id")
        user = User.objects.get(id=user_id)

        # 檢查是否已存在相同的權限關係
        if ClinicUserPermission.objects.filter(clinic=clinic, user=user).exists():
            return Response(
                {"error": "該用戶已擁有此診所的權限"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 創建權限關係
        serializer.save(
            clinic=clinic,
            user=user,
            create_user=request.user if request.user.is_authenticated else None,
        )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @extend_schema(
        tags=["Clinic Permissions"],
        summary="Retrieve clinic user permission",
        description="獲取診所用戶權限詳細資訊。",
    )
    def retrieve(self, request, *args, **kwargs):
        """獲取診所用戶權限詳細資訊"""
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        tags=["Clinic Permissions"],
        summary="Update clinic user permission",
        description="""
        更新診所用戶權限關係。

        使用 PUT 進行完整更新，或使用 PATCH 進行部分更新。
        """,
        examples=[
            OpenApiExample(
                "Update Permission Request (PATCH)",
                value={"clinic_id": 2, "user_id": 1},
                request_only=True,
            ),
        ],
    )
    def update(self, request, *args, **kwargs):
        """更新診所用戶權限"""
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # 如果更新了 clinic_id，獲取診所對象（已在 serializer 中驗證）
        if "clinic_id" in serializer.validated_data:
            clinic_id = serializer.validated_data.pop("clinic_id")
            clinic = Clinic.objects.get(id=clinic_id)
            serializer.validated_data["clinic"] = clinic

        # 如果更新了 user_id，獲取用戶對象（已在 serializer 中驗證）
        if "user_id" in serializer.validated_data:
            user_id = serializer.validated_data.pop("user_id")
            user = User.objects.get(id=user_id)
            serializer.validated_data["user"] = user

        # 檢查更新後的組合是否已存在（排除當前實例）
        clinic = serializer.validated_data.get("clinic", instance.clinic)
        user = serializer.validated_data.get("user", instance.user)

        if (
            ClinicUserPermission.objects.filter(clinic=clinic, user=user)
            .exclude(id=instance.id)
            .exists()
        ):
            return Response(
                {"error": "該用戶已擁有此診所的權限"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        self.perform_update(serializer)

        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    @extend_schema(
        tags=["Clinic Permissions"],
        summary="Partial update clinic user permission",
        description="部分更新診所用戶權限關係（PATCH）。",
    )
    def partial_update(self, request, *args, **kwargs):
        """部分更新診所用戶權限"""
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    @extend_schema(
        tags=["Clinic Permissions"],
        summary="Delete clinic user permission",
        description="刪除診所用戶權限關係。",
    )
    def destroy(self, request, *args, **kwargs):
        """刪除診所用戶權限"""
        return super().destroy(request, *args, **kwargs)


class SubmitCertificateApplicationView(APIView):
    """
    API endpoint to submit a certificate application.

    POST /api/certificates/submit-application/
    This endpoint receives form data and clinic information, generates a verification token,
    and sends a verification email to the clinic.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Certificates"],
        summary="Submit certificate application",
        description="""
        提交證書申請。

        **流程說明：**
        1. 接收表單資料和診所資訊
        2. 生成驗證 token（有效期 7 天）
        3. 發送驗證 email 到診所
        4. 返回申請 ID 和狀態

        **注意事項：**
        - certificate_data 必須包含 email 欄位
        - certificate_data 可選包含 tx- 開頭的模板欄位值
        - 驗證 email 會發送到診所的 email 地址
        """,
        request=CertificateApplicationCreateSerializer,
        examples=[
            OpenApiExample(
                "Request Example",
                value={
                    "user_id": 1,
                    "clinic_id": 1,
                    "certificate_data": {
                        "email": "member@example.com",
                        "tx-101": "獎狀",
                        "tx-103": "張三",
                    },
                },
                request_only=True,
            ),
        ],
        responses={
            201: OpenApiResponse(
                description="申請提交成功",
                response=inline_serializer(
                    name="SubmitApplicationResponse",
                    fields={
                        "application_id": serializers.IntegerField(help_text="申請 ID"),
                        "status": serializers.CharField(help_text="申請狀態"),
                        "message": serializers.CharField(help_text="成功訊息"),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="請求資料錯誤",
                response=inline_serializer(
                    name="SubmitApplicationErrorResponse",
                    fields={
                        "error": serializers.CharField(help_text="錯誤訊息"),
                        "details": serializers.DictField(
                            required=False, help_text="詳細錯誤資訊"
                        ),
                    },
                ),
            ),
            404: OpenApiResponse(
                description="用戶或診所不存在",
                response=inline_serializer(
                    name="SubmitApplicationNotFoundResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
        },
    )
    def post(self, request):
        """
        提交證書申請
        """
        serializer = CertificateApplicationCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "請求資料錯誤", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = serializer.validated_data

        # 驗證用戶是否存在
        try:
            user = User.objects.get(id=data["user_id"])
        except User.DoesNotExist:
            return Response({"error": "用戶不存在"}, status=status.HTTP_404_NOT_FOUND)

        # 驗證診所是否存在
        try:
            clinic = Clinic.objects.get(id=data["clinic_id"])
        except Clinic.DoesNotExist:
            return Response({"error": "診所不存在"}, status=status.HTTP_404_NOT_FOUND)

        # 檢查診所是否有 email
        if not clinic.email:
            return Response(
                {"error": "診所未設置電子郵件地址"}, status=status.HTTP_400_BAD_REQUEST
            )

        # 驗證 certificate_data 包含 email
        certificate_data = data.get("certificate_data", {})
        if not isinstance(certificate_data, dict):
            return Response(
                {"error": "certificate_data 必須是一個物件"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if "email" not in certificate_data or not certificate_data.get("email"):
            return Response(
                {"error": "certificate_data 必須包含有效的 email 欄位"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 使用事務確保數據一致性
        try:
            with transaction.atomic():
                # 創建證書申請實例（先不保存）
                application = CertificateApplication(
                    user=user,
                    clinic=clinic,
                    certificate_data=certificate_data,
                    create_user=request.user if request.user.is_authenticated else None,
                )

                # 生成驗證 token（這會設置 verification_token 和 token_expires_at）
                token = application.generate_verification_token()

                # 保存申請
                application.save()
        except Exception as e:
            logger.error(
                f"Failed to create certificate application: {e}", exc_info=True
            )
            return Response(
                {"error": "創建證書申請失敗，請稍後再試"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # 發送驗證 email（在事務外，避免影響數據保存）
        try:
            self._send_verification_email(application, token)
        except Exception as e:
            logger.error(
                f"Failed to send verification email for application {application.id}: {e}",
                exc_info=True,
            )
            # 即使發送失敗，也返回成功（可以稍後重試或手動發送）

        return Response(
            {
                "application_id": application.id,
                "status": application.status,
                "message": "申請已提交，驗證 email 已發送到診所",
            },
            status=status.HTTP_201_CREATED,
        )

    def _send_verification_email(self, application, token):
        """
        發送驗證 email 到診所

        Args:
            application: CertificateApplication 實例
            token: 驗證 token

        Raises:
            Exception: 如果發送失敗
        """
        if not application.clinic.email:
            raise ValueError(
                f"Clinic {application.clinic.id} does not have an email address"
            )

        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        # 構建驗證連結
        verification_url = f"{frontend_url}/certificate/verify?token={token}"

        # 構建 email 內容
        subject = "證書申請驗證 - 請確認證書發放"

        # 從用戶獲取申請人資訊
        applicant_name = application.get_applicant_name()
        applicant_email = application.get_applicant_email()
        applicant_phone = application.get_applicant_phone()
        surgeon_name = application.certificate_data.get("surgeon_name", "未提供")
        surgery_date = application.certificate_data.get("surgery_date", "未提供")

        submitted_at = application.create_time.strftime("%Y-%m-%d %H:%M:%S")
        button_styles = (
            "background-color: #4CAF50; color: white; padding: 10px 20px; "
            "text-decoration: none; border-radius: 5px; display: inline-block;"
        )
        applicant_phone_item = ""
        if applicant_phone:
            applicant_phone_item = (
                "<li><strong>申請人電話：</strong>" f"{applicant_phone}</li>"
            )

        # 使用 HTML 模板
        html_message = f"""
        <html>
        <body>
            <h2>證書申請驗證</h2>
            <p>親愛的 {application.clinic.name} 診所：</p>
            <p>您收到一份證書申請，申請人資訊如下：</p>
            <ul>
                <li><strong>申請人姓名：</strong>{applicant_name}</li>
                <li><strong>申請人電子郵件：</strong>{applicant_email}</li>
                {applicant_phone_item}
                <li><strong>手術醫師：</strong>{surgeon_name}</li>
                <li><strong>手術日期：</strong>{surgery_date or '未提供'}</li>
                <li><strong>申請時間：</strong>{submitted_at}</li>
            </ul>
            <p>請點擊以下連結確認並完成證書發放：</p>
            <p>
                <a href="{verification_url}" style="{button_styles}">
                    確認並發放證書
                </a>
            </p>
            <p>或複製以下連結到瀏覽器：</p>
            <p>{verification_url}</p>
            <p><small>此連結將在 7 天後過期</small></p>
            <hr>
            <p><small>此為系統自動發送，請勿回覆此郵件。</small></p>
        </body>
        </html>
        """

        plain_message = strip_tags(html_message)

        # 發送 email（使用密件副本保護個資）
        from django.core.mail import EmailMultiAlternatives

        email_msg = EmailMultiAlternatives(
            subject=subject,
            body=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[],  # 使用空列表，避免在 To 欄位顯示收件人
            bcc=[application.clinic.email],  # 使用密件副本保護個資
        )
        email_msg.attach_alternative(html_message, "text/html")
        email_msg.send(fail_silently=False)

        logger.info(
            "Verification email sent successfully to %s for application %s "
            "(user: %s, clinic: %s)",
            application.clinic.email,
            application.id,
            application.user.id,
            application.clinic.id,
        )


class VerifyCertificateTokenView(APIView):
    """
    API endpoint to verify certificate application token.

    GET /api/certificates/verify-token/?token=<token>
    This endpoint verifies the token and returns application information.
    """

    permission_classes = [
        AllowAny
    ]  # 允許未登入用戶訪問，因為這是從 email 連結點擊進來的

    @extend_schema(
        tags=["Certificates"],
        summary="Verify certificate application token",
        description="""
        驗證證書申請 token。

        **流程說明：**
        1. 接收 token 參數
        2. 驗證 token 是否有效（未過期且狀態為 pending）
        3. 返回申請資訊

        **注意事項：**
        - Token 有效期為 7 天
        - 只有狀態為 pending 的申請可以驗證
        - 驗證成功後，前端可以調用發證 API
        """,
        parameters=[
            OpenApiParameter(
                name="token",
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description="驗證 token",
            )
        ],
        responses={
            200: OpenApiResponse(
                description="Token 驗證成功",
                response=inline_serializer(
                    name="VerifyTokenResponse",
                    fields={
                        "valid": serializers.BooleanField(help_text="Token 是否有效"),
                        "application": CertificateApplicationSerializer(),
                        "message": serializers.CharField(help_text="狀態訊息"),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="Token 無效或已過期",
                response=inline_serializer(
                    name="VerifyTokenErrorResponse",
                    fields={
                        "valid": serializers.BooleanField(help_text="Token 是否有效"),
                        "error": serializers.CharField(help_text="錯誤訊息"),
                        "status": serializers.CharField(
                            required=False, help_text="申請狀態"
                        ),
                    },
                ),
            ),
        },
    )
    def get(self, request):
        """
        驗證 token
        """
        token = request.query_params.get("token")

        if not token:
            return Response(
                {"valid": False, "error": "缺少 token 參數"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            application = CertificateApplication.objects.get(verification_token=token)
        except CertificateApplication.DoesNotExist:
            return Response(
                {"valid": False, "error": "無效的 token，找不到對應的證書申請"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 檢查 token 是否有效
        if not application.is_token_valid():
            # 提供更詳細的錯誤訊息
            error_message = "Token 已過期或已被使用"
            if application.status == CertificateApplicationStatus.ISSUED:
                error_message = "此證書申請已經發證，無法再次驗證"
            elif application.status == CertificateApplicationStatus.EXPIRED:
                error_message = "Token 已過期（有效期為 7 天）"
            elif application.status == CertificateApplicationStatus.CANCELLED:
                error_message = "此證書申請已被取消"

            return Response(
                {
                    "valid": False,
                    "error": error_message,
                    "status": application.status,
                    "status_display": application.get_status_display(),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 標記為已驗證（如果還是 pending 狀態）
        if application.status == CertificateApplicationStatus.PENDING:
            try:
                application.mark_as_verified()
            except Exception as e:
                logger.error(
                    f"Failed to mark application {application.id} as verified: {e}",
                    exc_info=True,
                )
                return Response(
                    {"error": "更新申請狀態失敗，請稍後再試"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        serializer = CertificateApplicationSerializer(application)

        return Response(
            {
                "valid": True,
                "application": serializer.data,
                "message": "Token 驗證成功",
            },
            status=status.HTTP_200_OK,
        )


class CertificateApplicationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing certificate applications.

    Provides CRUD operations for certificate applications:
    - List: GET /api/certificate-applications/ (with filtering, searching, ordering)
    - Create: POST /api/certificate-applications/
    - Retrieve: GET /api/certificate-applications/{id}/
    - Update: PUT/PATCH /api/certificate-applications/{id}/
    - Delete: DELETE /api/certificate-applications/{id}/
    """

    queryset = (
        CertificateApplication.objects.select_related(
            "user", "clinic", "consultation_clinic"
        )
        .all()
        .order_by("-create_time")
    )
    serializer_class = CertificateApplicationSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    filterset_class = CertificateApplicationFilterSet
    ordering_fields = [
        "status",
        "create_time",
        "update_time",
        "verified_at",
        "issued_at",
        "surgeon_name",
        "consultant_name",
    ]
    ordering = ["-create_time"]
    search_fields = [
        "surgeon_name",
        "consultant_name",
        "user__username",
        "user__email",
        "clinic__name",
        "consultation_clinic__name",
    ]
    pagination_class = StandardResultsSetPagination

    def _check_certificate_application_permission(self, user, application):
        """
        檢查用戶是否有權限訪問指定的證書申請（調用獨立函數）
        """
        return check_certificate_application_permission(user, application)

    def get_queryset(self):
        """
        根據用戶角色過濾證書申請：
        - 超級管理員和管理員：可以查看所有申請
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能查看與他們有 ClinicUserPermission 關聯的診所相關的申請
        - 普通用戶（CLIENT）：只能查看自己的申請
        """
        queryset = super().get_queryset()

        # 檢查用戶角色
        user = self.request.user

        if not hasattr(user, "role"):
            return queryset.none()

        # 超級管理員和管理員可以查看所有申請
        if user.role in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
            return queryset

        # 診所管理員和診所員工只能查看與他們有 ClinicUserPermission 關聯的診所相關的申請
        if user.role in [UserRole.CLINIC_ADMIN, UserRole.CLINIC_STAFF]:
            # 獲取該用戶有權限的診所 ID 列表
            permitted_clinic_ids = ClinicUserPermission.objects.filter(
                user=user
            ).values_list("clinic_id", flat=True)

            # 過濾證書申請，只返回這些診所的申請
            return queryset.filter(clinic_id__in=permitted_clinic_ids)

        # 普通用戶只能查看自己的申請
        if user.role == UserRole.CLIENT:
            return queryset.filter(user=user)

        # 其他角色返回空查詢集
        return queryset.none()

    @extend_schema(
        tags=["Certificate Applications"],
        summary="List certificate applications",
        description="""
        獲取證書申請列表。

        **權限說明：**
        - 超級管理員和管理員：可以查看所有申請
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能查看與他們有 ClinicUserPermission 關聯的診所相關的申請
        - 普通用戶（CLIENT）：只能查看自己的申請

        **查詢參數：**
        - `user`: 用戶 ID（可選，用於篩選特定用戶的申請，普通用戶只能查詢自己的）
        - `clinic`: 診所 ID（可選，用於篩選特定診所的申請）
        - `consultation_clinic`: 諮詢診所 ID（可選）
        - `status`: 申請狀態（可選，pending/verified/issued/expired/cancelled）
        - `surgeon_name`: 手術醫師姓名（可選，部分匹配）
        - `consultant_name`: 諮詢師姓名（可選，部分匹配）
        - `create_time__gte`: 建立時間（大於等於）
        - `create_time__lte`: 建立時間（小於等於）
        - `search`: 搜尋關鍵字（可選，會搜尋手術醫師、諮詢師、用戶名、用戶 email、診所名稱）
        - `ordering`: 排序欄位（可選，如：create_time, -create_time, status）
        """,
        parameters=[
            OpenApiParameter(
                name="user",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description="用戶 ID（用於篩選特定用戶的申請）",
            ),
            OpenApiParameter(
                name="clinic",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description="診所 ID（用於篩選特定診所的申請）",
            ),
            OpenApiParameter(
                name="status",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="申請狀態（pending/verified/issued/expired）",
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        """獲取證書申請列表"""
        return super().list(request, *args, **kwargs)

    @extend_schema(
        tags=["Certificate Applications"],
        summary="Create certificate application",
        description="""
        創建證書申請。

        **必填欄位：**
        - `user_id`: 用戶 ID（會員 ID）
        - `clinic_id`: 診所 ID

        **可選欄位：**
        - `consultation_clinic_id`: 諮詢診所 ID
        - `surgeon_name`: 手術醫師姓名
        - `consultant_name`: 諮詢師姓名
        - `certificate_data`: 證書資料（JSON 格式，必須包含 email 欄位）

        **注意事項：**
        - certificate_data 必須包含 email 欄位
        - 創建後會自動生成驗證 token（有效期 7 天）
        - 初始狀態為 pending
        """,
        examples=[
            OpenApiExample(
                "Create Application Request",
                value={
                    "user_id": 1,
                    "clinic_id": 1,
                    "consultation_clinic_id": 2,
                    "surgeon_name": "王醫師",
                    "consultant_name": "李諮詢師",
                    "certificate_data": {
                        "email": "member@example.com",
                        "tx-101": "獎狀",
                        "tx-103": "張三",
                    },
                },
                request_only=True,
            ),
        ],
    )
    def create(self, request, *args, **kwargs):
        """創建證書申請"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # 驗證必填欄位
        if "user_id" not in serializer.validated_data:
            return Response(
                {"error": "user_id 是必填欄位"}, status=status.HTTP_400_BAD_REQUEST
            )

        if "clinic_id" not in serializer.validated_data:
            return Response(
                {"error": "clinic_id 是必填欄位"}, status=status.HTTP_400_BAD_REQUEST
            )

        # 獲取用戶和診所（已在 serializer 中驗證）
        user_id = serializer.validated_data.pop("user_id")
        user = User.objects.get(id=user_id)

        clinic_id = serializer.validated_data.pop("clinic_id")
        clinic = Clinic.objects.get(id=clinic_id)

        # 處理諮詢診所（可選）
        consultation_clinic_id = serializer.validated_data.pop(
            "consultation_clinic_id", None
        )
        consultation_clinic = (
            Clinic.objects.get(id=consultation_clinic_id)
            if consultation_clinic_id
            else None
        )

        # 驗證 certificate_data 包含 email（如果提供了）
        certificate_data = serializer.validated_data.get("certificate_data", {})
        if certificate_data and isinstance(certificate_data, dict):
            if "email" not in certificate_data or not certificate_data.get("email"):
                return Response(
                    {"error": "certificate_data 必須包含有效的 email 欄位"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # 使用事務確保數據一致性
        try:
            with transaction.atomic():
                # 先創建實例但不保存（因為需要先生成 token）
                application = CertificateApplication(
                    user=user,
                    clinic=clinic,
                    consultation_clinic=consultation_clinic,
                    certificate_data=serializer.validated_data.get(
                        "certificate_data", {}
                    ),
                    surgeon_name=serializer.validated_data.get("surgeon_name"),
                    consultant_name=serializer.validated_data.get("consultant_name"),
                    status=serializer.validated_data.get(
                        "status", CertificateApplicationStatus.PENDING
                    ),
                    create_user=request.user if request.user.is_authenticated else None,
                )

                # 生成驗證 token（這會設置 verification_token 和 token_expires_at）
                application.generate_verification_token()

                # 保存申請
                application.save()
        except Exception as e:
            logger.error(
                f"Failed to create certificate application: {e}", exc_info=True
            )
            return Response(
                {"error": "創建證書申請失敗，請稍後再試"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @extend_schema(
        tags=["Certificate Applications"],
        summary="Retrieve certificate application",
        description="""
        獲取證書申請詳細資訊。

        **權限說明：**
        - 超級管理員和管理員：可以查看所有申請
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能查看與他們有 ClinicUserPermission 關聯的診所相關的申請
        - 普通用戶（CLIENT）：只能查看自己的申請
        """,
    )
    def retrieve(self, request, *args, **kwargs):
        """獲取證書申請詳細資訊"""
        instance = self.get_object()

        # 檢查權限
        has_permission, error_message = self._check_certificate_application_permission(
            request.user, instance
        )
        if not has_permission:
            return Response({"error": error_message}, status=status.HTTP_403_FORBIDDEN)

        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        tags=["Certificate Applications"],
        summary="Update certificate application",
        description="""
        更新證書申請。

        使用 PUT 進行完整更新，或使用 PATCH 進行部分更新。

        **權限說明：**
        - 超級管理員和管理員：可以更新所有申請
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能更新與他們有 ClinicUserPermission 關聯的診所相關的申請
        - 普通用戶（CLIENT）：只能更新自己的申請

        **注意事項：**
        - 某些欄位是只讀的（如 verification_token, verified_at, issued_at 等）
        - 更新 certificate_data 時，如果包含 email 欄位，必須是有效的 email
        - 狀態變更應該通過專門的 API 進行（如驗證、發證等）
        """,
        examples=[
            OpenApiExample(
                "Update Application Request (PATCH)",
                value={
                    "surgeon_name": "王醫師（已更新）",
                    "consultant_name": "李諮詢師（已更新）",
                    "certificate_data": {
                        "email": "newemail@example.com",
                        "tx-101": "獎狀（更新）",
                    },
                },
                request_only=True,
            ),
        ],
    )
    def update(self, request, *args, **kwargs):
        """更新證書申請"""
        partial = kwargs.pop("partial", False)
        instance = self.get_object()

        # 檢查權限
        has_permission, error_message = self._check_certificate_application_permission(
            request.user, instance
        )
        if not has_permission:
            return Response({"error": error_message}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # 如果更新了 user_id，獲取用戶對象（已在 serializer 中驗證）
        if "user_id" in serializer.validated_data:
            user_id = serializer.validated_data.pop("user_id")
            user = User.objects.get(id=user_id)
            serializer.validated_data["user"] = user

        # 如果更新了 clinic_id，獲取診所對象（已在 serializer 中驗證）
        if "clinic_id" in serializer.validated_data:
            clinic_id = serializer.validated_data.pop("clinic_id")
            clinic = Clinic.objects.get(id=clinic_id)
            serializer.validated_data["clinic"] = clinic

        # 如果更新了 consultation_clinic_id，獲取諮詢診所對象（已在 serializer 中驗證）
        if "consultation_clinic_id" in serializer.validated_data:
            consultation_clinic_id = serializer.validated_data.pop(
                "consultation_clinic_id"
            )
            consultation_clinic = (
                Clinic.objects.get(id=consultation_clinic_id)
                if consultation_clinic_id
                else None
            )
            serializer.validated_data["consultation_clinic"] = consultation_clinic

        # 驗證 certificate_data 包含 email（如果提供了）
        certificate_data = serializer.validated_data.get("certificate_data")
        if certificate_data and isinstance(certificate_data, dict):
            if "email" not in certificate_data or not certificate_data.get("email"):
                return Response(
                    {"error": "certificate_data 必須包含有效的 email 欄位"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # 記錄舊狀態（在更新前）
        instance.status

        self.perform_update(serializer)

        # 注意：取消通知 email 會由 signal 自動發送（clinic/signals.py）

        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    @extend_schema(
        tags=["Certificate Applications"],
        summary="Partial update certificate application",
        description="""
        部分更新證書申請（PATCH）。

        **權限說明：**
        - 超級管理員和管理員：可以更新所有申請
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能更新與他們有 ClinicUserPermission 關聯的診所相關的申請
        - 普通用戶（CLIENT）：只能更新自己的申請
        """,
    )
    def partial_update(self, request, *args, **kwargs):
        """部分更新證書申請"""
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    @extend_schema(
        tags=["Certificate Applications"],
        summary="Delete certificate application",
        description="""
        刪除證書申請。

        **權限說明：**
        - 超級管理員和管理員：可以刪除所有申請
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能刪除與他們有 ClinicUserPermission 關聯的診所相關的申請
        - 普通用戶（CLIENT）：只能刪除自己的申請
        """,
    )
    def destroy(self, request, *args, **kwargs):
        """刪除證書申請"""
        instance = self.get_object()

        # 檢查權限
        has_permission, error_message = self._check_certificate_application_permission(
            request.user, instance
        )
        if not has_permission:
            return Response({"error": error_message}, status=status.HTTP_403_FORBIDDEN)

        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        tags=["Certificate Applications"],
        summary="Toggle certificate application status (pending/cancelled)",
        description="""
        切換證書申請狀態（pending ↔ cancelled）。

        **權限要求：**
        - 申請人本人可以切換自己申請的狀態
        - 後台權限人員（管理員、診所管理員、診所員工）也可以切換任何申請的狀態

        **功能說明：**
        - 如果當前狀態為 `pending`，則切換為 `cancelled`
        - 如果當前狀態為 `cancelled`，則切換為 `pending`
        - 其他狀態不允許切換

        **權限限制：**
        - 一般會員（CLIENT）：只能取消證書（pending → cancelled），不能回復（cancelled → pending）
        - 超級管理員和管理員：可以取消和回復證書
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能取消和回復與他們有 ClinicUserPermission 關聯的診所相關的證書

        **注意事項：**
        - 只有申請人本人可以執行此操作
        - 只能從 `pending` 切換到 `cancelled`，或從 `cancelled` 切換到 `pending`
        - 其他狀態（verified、issued、expired）不允許切換
        """,
        request=None,
        responses={
            200: OpenApiResponse(
                description="狀態切換成功",
                response=inline_serializer(
                    name="ToggleStatusSuccessResponse",
                    fields={
                        "success": serializers.BooleanField(help_text="是否成功"),
                        "application_id": serializers.IntegerField(help_text="申請 ID"),
                        "old_status": serializers.CharField(help_text="原狀態"),
                        "new_status": serializers.CharField(help_text="新狀態"),
                        "message": serializers.CharField(help_text="成功訊息"),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="請求錯誤（狀態不允許切換或不是申請人）",
                response=inline_serializer(
                    name="ToggleStatusErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            403: OpenApiResponse(
                description="權限不足（不是申請人）",
                response=inline_serializer(
                    name="ToggleStatusForbiddenResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            404: OpenApiResponse(
                description="申請不存在",
                response=inline_serializer(
                    name="ToggleStatusNotFoundResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
        },
    )
    @action(
        detail=True,
        methods=["post"],
        url_path="toggle-status",
        url_name="toggle-status",
    )
    def toggle_status(self, request, pk=None):
        """
        切換證書申請狀態（pending ↔ cancelled）

        申請人本人或後台權限人員可以執行此操作
        """
        try:
            application = self.get_object()
        except CertificateApplication.DoesNotExist:
            return Response(
                {"error": "證書申請不存在"}, status=status.HTTP_404_NOT_FOUND
            )

        # 檢查權限：只有申請人本人或後台權限人員可以切換狀態
        user = request.user

        # 如果是申請人本人，允許切換
        if application.user == user:
            pass  # 允許繼續
        else:
            # 檢查後台權限人員是否有權限訪問此申請
            has_permission, error_message = (
                self._check_certificate_application_permission(user, application)
            )
            if not has_permission:
                return Response(
                    {
                        "error": error_message
                        or "只有申請人本人或後台權限人員可以切換申請狀態"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

        # 檢查當前狀態是否允許切換
        current_status = application.status
        if current_status not in [
            CertificateApplicationStatus.PENDING,
            CertificateApplicationStatus.CANCELLED,
        ]:
            return Response(
                {
                    "error": f"當前狀態為 {application.get_status_display()}，不允許切換。只能切換 pending 和 cancelled 狀態。",
                    "current_status": current_status,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 檢查用戶角色和權限（已在上面定義）
        is_client = hasattr(user, "role") and user.role == UserRole.CLIENT

        # 如果是普通用戶且當前狀態為 cancelled，不允許回復
        if is_client and current_status == CertificateApplicationStatus.CANCELLED:
            return Response(
                {
                    "error": "一般會員只能取消證書，不能回復。如需回復，請聯繫管理員。",
                    "current_status": current_status,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # 切換狀態
        old_status = current_status
        if current_status == CertificateApplicationStatus.PENDING:
            new_status = CertificateApplicationStatus.CANCELLED
        else:  # current_status == CertificateApplicationStatus.CANCELLED
            new_status = CertificateApplicationStatus.PENDING

        try:
            with transaction.atomic():
                application.status = new_status
                application.save(update_fields=["status", "update_time"])

            logger.info(
                f"Certificate application {application.id} status changed from {old_status} to {new_status} "
                f"by user {request.user.id}"
            )

            # 注意：取消通知 email 會由 signal 自動發送（clinic/signals.py）

            # 獲取狀態顯示名稱
            application.status = old_status
            old_status_display = application.get_status_display()
            application.status = new_status
            new_status_display = application.get_status_display()

            return Response(
                {
                    "success": True,
                    "application_id": application.id,
                    "old_status": old_status,
                    "old_status_display": old_status_display,
                    "new_status": new_status,
                    "new_status_display": new_status_display,
                    "message": f"狀態已從 {old_status_display} 切換為 {new_status_display}",
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(
                f"Failed to toggle status for application {application.id}: {e}",
                exc_info=True,
            )
            return Response(
                {"error": "狀態切換失敗，請稍後再試"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @extend_schema(
        tags=["Certificate Applications"],
        summary="Resend verification email (Admin only)",
        description="""
        重新發送驗證 email 信件（僅限後台權限人員）。

        **權限要求：**
        - 只有後台權限人員（管理員、診所管理員、診所員工）可以使用
        - 一般會員無法使用此功能

        **功能說明：**
        - 重新發送驗證 email 到診所的 email 地址
        - 只能對狀態為 `pending` 的申請重新發送
        - 使用現有的驗證 token（不會生成新的 token）

        **注意事項：**
        - 申請狀態必須是 `pending`
        - 申請必須有驗證 token
        - 診所必須有 email 地址
        """,
        request=None,
        responses={
            200: OpenApiResponse(
                description="驗證 email 重新發送成功",
                response=inline_serializer(
                    name="ResendEmailSuccessResponse",
                    fields={
                        "success": serializers.BooleanField(help_text="是否成功"),
                        "application_id": serializers.IntegerField(help_text="申請 ID"),
                        "status": serializers.CharField(help_text="申請狀態"),
                        "message": serializers.CharField(help_text="成功訊息"),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="請求錯誤（狀態不是 pending 或缺少必要資訊）",
                response=inline_serializer(
                    name="ResendEmailErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            403: OpenApiResponse(
                description="權限不足（不是後台權限人員）",
                response=inline_serializer(
                    name="ResendEmailForbiddenResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            404: OpenApiResponse(
                description="申請不存在",
                response=inline_serializer(
                    name="ResendEmailNotFoundResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            500: OpenApiResponse(
                description="發送 email 失敗",
                response=inline_serializer(
                    name="ResendEmailServerErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
        },
    )
    @action(
        detail=True,
        methods=["post"],
        url_path="resend-verification-email",
        url_name="resend-verification-email",
        permission_classes=[IsAuthenticated, IsStaffRolePermission],
    )
    def resend_verification_email(self, request, pk=None):
        """
        重新發送驗證 email 信件（僅限後台權限人員）

        只有後台權限人員可以執行此操作
        """
        try:
            application = self.get_object()
        except CertificateApplication.DoesNotExist:
            return Response(
                {"error": "證書申請不存在"}, status=status.HTTP_404_NOT_FOUND
            )

        # 檢查權限：後台權限人員必須有權限訪問此診所的申請
        has_permission, error_message = self._check_certificate_application_permission(
            request.user, application
        )
        if not has_permission:
            return Response(
                {"error": error_message or "您沒有權限訪問此診所的證書申請"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 檢查申請狀態必須是 pending
        if application.status != CertificateApplicationStatus.PENDING:
            return Response(
                {
                    "error": f"只能重新發送 pending 狀態的申請驗證 email，當前狀態：{application.get_status_display()}",
                    "current_status": application.status,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 檢查申請是否有驗證 token
        if not application.verification_token:
            return Response(
                {"error": "申請缺少驗證 token，無法重新發送驗證 email"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 檢查診所是否有 email
        if not application.clinic or not application.clinic.email:
            return Response(
                {"error": "診所未設置電子郵件地址，無法發送驗證 email"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 重新發送驗證 email
        try:
            self._send_verification_email(application, application.verification_token)

            logger.info(
                f"Verification email resent for application {application.id} "
                f"by staff user {request.user.id}"
            )

            return Response(
                {
                    "success": True,
                    "application_id": application.id,
                    "status": application.status,
                    "message": f"驗證 email 已重新發送到 {application.clinic.email}",
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(
                f"Failed to resend verification email for application {application.id}: {e}",
                exc_info=True,
            )
            return Response(
                {"error": "發送驗證 email 失敗，請稍後再試"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _send_verification_email(self, application, token):
        """
        發送驗證 email 到診所

        Args:
            application: CertificateApplication 實例
            token: 驗證 token

        Raises:
            Exception: 如果發送失敗
        """
        if not application.clinic.email:
            raise ValueError(
                f"Clinic {application.clinic.id} does not have an email address"
            )

        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        # 構建驗證連結
        verification_url = f"{frontend_url}/certificate/verify?token={token}"

        # 構建 email 內容
        subject = "證書申請驗證 - 請確認證書發放"

        # 從用戶獲取申請人資訊
        applicant_name = application.get_applicant_name()
        applicant_email = application.get_applicant_email()
        applicant_phone = application.get_applicant_phone()
        surgeon_name = application.certificate_data.get("surgeon_name", "未提供")
        surgery_date = application.certificate_data.get("surgery_date", "未提供")
        created_at = application.create_time.strftime("%Y-%m-%d %H:%M:%S")
        token_expiry = (
            application.token_expires_at.strftime("%Y-%m-%d %H:%M:%S")
            if application.token_expires_at
            else "7天"
        )
        button_styles = (
            "background-color: #4CAF50; color: white; padding: 10px 20px; "
            "text-decoration: none; border-radius: 5px;"
        )
        applicant_name = applicant_name or "未提供"
        applicant_email = applicant_email or "未提供"
        applicant_phone = applicant_phone or "未提供"
        surgeon_name = surgeon_name or "未提供"
        surgery_date = surgery_date or "未提供"

        # 使用 HTML 模板
        html_message = f"""
        <html>
        <body>
            <h2>證書申請驗證</h2>
            <p>親愛的診所管理員，</p>
            <p>您收到一筆新的證書申請，請確認以下資訊：</p>
            <ul>
                <li>
                    <strong>申請人姓名：</strong>{applicant_name}
                </li>
                <li>
                    <strong>申請人 Email：</strong>{applicant_email}
                </li>
                <li>
                    <strong>申請人電話：</strong>{applicant_phone}
                </li>
                <li>
                    <strong>手術醫師：</strong>{surgeon_name}
                </li>
                <li>
                    <strong>手術日期：</strong>{surgery_date}
                </li>
                <li>
                    <strong>申請時間：</strong>{created_at}
                </li>
            </ul>
            <p>請點擊以下連結確認並驗證此申請：</p>
            <p>
                <a href="{verification_url}" style="{button_styles}">
                    確認證書申請
                </a>
            </p>
            <p>或複製以下連結到瀏覽器：</p>
            <p>{verification_url}</p>
            <p>此連結將在 {token_expiry} 後過期。</p>
            <p>如果您沒有提交此申請，請忽略此 email。</p>
            <p>謝謝！</p>
        </body>
        </html>
        """

        # 純文字版本（用於不支持 HTML 的 email 客戶端）
        plain_message = strip_tags(html_message)

        # 發送 email（使用密件副本保護個資）
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[],  # 使用空列表，避免在 To 欄位顯示收件人
            bcc=[application.clinic.email],  # 使用密件副本保護個資
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(
            f"Verification email sent successfully to {application.clinic.email} "
            f"for application {application.id} (user: {application.user.id}, clinic: {application.clinic.id})"
        )

    def _send_cancellation_email(self, application):
        """
        發送取消通知 email 給申請人

        Args:
            application: CertificateApplication 實例

        Raises:
            Exception: 如果發送失敗
        """
        # 獲取申請人 email（優先從 certificate_data，否則從 user）
        applicant_email = None
        if application.certificate_data and isinstance(
            application.certificate_data, dict
        ):
            applicant_email = application.certificate_data.get("email")

        if not applicant_email and application.user:
            applicant_email = application.user.email

        if not applicant_email:
            raise ValueError(
                f"Application {application.id} does not have applicant email address"
            )

        # 構建 email 內容
        subject = "證書申請已取消"

        # 獲取申請人資訊
        applicant_name = application.get_applicant_name() or "申請人"
        clinic_name = application.clinic.name if application.clinic else "診所"

        # 使用 HTML 模板
        html_message = f"""
        <html>
        <body>
            <h2>證書申請已取消</h2>
            <p>親愛的 {applicant_name}，</p>
            <p>您的證書申請已被取消。</p>
            <ul>
                <li><strong>申請編號：</strong>#{application.id}</li>
                <li><strong>診所名稱：</strong>{clinic_name}</li>
                <li><strong>申請時間：</strong>{application.create_time.strftime('%Y-%m-%d %H:%M:%S')}</li>
                <li><strong>取消時間：</strong>{application.update_time.strftime('%Y-%m-%d %H:%M:%S')}</li>
            </ul>
            <p>如有任何疑問，請聯繫相關診所或系統管理員。</p>
            <hr>
            <p><small>此為系統自動發送，請勿回覆此郵件。</small></p>
        </body>
        </html>
        """

        # 純文字版本（用於不支持 HTML 的 email 客戶端）
        plain_message = strip_tags(html_message)

        # 發送 email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[applicant_email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(
            f"Cancellation email sent successfully to {applicant_email} "
            f"for application {application.id}"
        )


class IssueCertificateView(APIView):
    """
    API endpoint to issue certificate for a certificate application.

    POST /api/certificates/issue/
    This endpoint issues a certificate for a verified certificate application.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Certificates"],
        summary="Issue certificate for application",
        description="""
        發放證書申請的證書。

        **流程說明：**
        1. 接收申請 ID 和可選的發證參數
        2. 驗證申請狀態（必須是 verified 或 pending）
        3. 獲取證書模板資訊
        4. 構建證書資料
        5. 根據環境變數 `CERTIFICATE_GROUP_ID` 決定發證方式：
           - 如果環境變數 `CERTIFICATE_GROUP_ID` 已配置：發證到現有群組
           - 如果環境變數未配置：發證到新群組
        6. 更新申請狀態為已發證（ISSUED）
        7. 保存證書 hash（如果返回）
        8. 返回證書群組 ID 和 hash

        **必填欄位：**
        - `application_id`: 證書申請 ID

        **可選欄位：**
        - `certRecordGroupId`: 已移除，改為從環境變數 `CERTIFICATE_GROUP_ID` 獲取
        - `name`: 證書群組名稱（僅在創建新群組時使用，默認：證書群組_{templateId}）
        - `certificateData`: 證書資料（如果未提供，將使用申請時提交的資料）
        - `isDownloadButtonEnabled`: 是否啟用下載按鈕（默認：true）
        - `skipSendingNotification`: 跳過發送通知（默認：True）
        - `setVisibilityPublic`: 設定為公開（默認：True）
        - `certRecordRemark`: 證書備註
        - `pdfProtectionPassword`: PDF 保護密碼
        - `autoNotificationTime`: 自動通知時間（ISO 8601 格式）
        - `customEmail`: 自訂電子郵件設定

        **權限說明：**
        - 超級管理員和管理員：可以發放所有申請的證書
        - 診所管理員和診所員工（CLINIC_ADMIN, CLINIC_STAFF）：只能發放與他們有 ClinicUserPermission 關聯的診所相關的證書
        - 普通用戶（CLIENT）：只能發放自己申請的證書

        **注意事項：**
        - 只有狀態為 verified 或 pending 的申請可以發證
        - 如果申請狀態為 pending，會自動標記為 verified
        - certificateData 必須包含 email 欄位（如果提供）
        - 如果未提供 certificateData，將使用申請時提交的 certificate_data
        - 證書完成發證後返回的 hash 會自動保存
        """,
        request=inline_serializer(
            name="IssueCertificateRequest",
            fields={
                "application_id": serializers.IntegerField(
                    required=True, help_text="證書申請 ID"
                ),
                "name": serializers.CharField(
                    required=False, help_text="證書群組名稱（僅在創建新群組時使用）"
                ),
                "certificateData": serializers.DictField(
                    required=False,
                    help_text="證書資料。必須包含 email 欄位，可選包含 tx- 開頭的模板欄位值。如果未提供，將使用申請時提交的資料。",
                ),
                "isDownloadButtonEnabled": serializers.BooleanField(
                    required=False, help_text="是否啟用下載按鈕"
                ),
                "skipSendingNotification": serializers.BooleanField(
                    required=False, help_text="跳過發送通知"
                ),
                "setVisibilityPublic": serializers.BooleanField(
                    required=False, help_text="設定為公開"
                ),
                "certRecordRemark": serializers.CharField(
                    required=False, help_text="證書備註"
                ),
                "pdfProtectionPassword": serializers.CharField(
                    required=False, help_text="PDF 保護密碼"
                ),
                "autoNotificationTime": serializers.CharField(
                    required=False, help_text="自動通知時間（ISO 8601 格式）"
                ),
                "customEmail": serializers.DictField(
                    required=False, help_text="自訂電子郵件設定"
                ),
            },
        ),
        examples=[
            OpenApiExample(
                "Request Example",
                value={
                    "application_id": 1,
                    "name": "證書群組名稱",
                    "isDownloadButtonEnabled": True,
                    "skipSendingNotification": True,
                    "setVisibilityPublic": True,
                    "certificateData": {
                        "email": "member@example.com",
                        "tx-101": "獎狀",
                        "tx-103": "張三",
                    },
                },
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="證書發放成功",
                response=inline_serializer(
                    name="IssueCertificateSuccessResponse",
                    fields={
                        "success": serializers.BooleanField(help_text="是否成功"),
                        "application_id": serializers.IntegerField(help_text="申請 ID"),
                        "certificate_group_id": serializers.IntegerField(
                            help_text="證書群組 ID"
                        ),
                        "certificate_hash": serializers.CharField(
                            required=False, help_text="證書 hash 值"
                        ),
                        "status": serializers.CharField(help_text="申請狀態"),
                        "message": serializers.CharField(help_text="成功訊息"),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="請求資料錯誤或申請狀態不正確",
                response=inline_serializer(
                    name="IssueCertificateErrorResponse",
                    fields={
                        "error": serializers.CharField(help_text="錯誤訊息"),
                        "details": serializers.DictField(
                            required=False, help_text="詳細錯誤資訊"
                        ),
                    },
                ),
            ),
            404: OpenApiResponse(
                description="申請不存在",
                response=inline_serializer(
                    name="IssueCertificateNotFoundResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            500: OpenApiResponse(
                description="內部服務器錯誤或外部 API 調用失敗",
                response=inline_serializer(
                    name="IssueCertificateServerErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
        },
    )
    def post(self, request):
        """
        發放證書申請的證書
        """
        application_id = request.data.get("application_id")

        if not application_id:
            return Response(
                {"error": "缺少 application_id 參數"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 獲取申請
        try:
            application = CertificateApplication.objects.select_related(
                "user", "clinic"
            ).get(id=application_id)
        except CertificateApplication.DoesNotExist:
            return Response(
                {"error": "證書申請不存在"}, status=status.HTTP_404_NOT_FOUND
            )

        # 檢查權限
        user = request.user
        has_permission, error_message = check_certificate_application_permission(
            user, application
        )
        if not has_permission:
            return Response(
                {"error": error_message or "您沒有權限發放此證書"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 檢查申請狀態（應該是 verified 或 pending）
        if application.status not in [
            CertificateApplicationStatus.VERIFIED,
            CertificateApplicationStatus.PENDING,
        ]:
            return Response(
                {
                    "error": f"申請狀態不正確，當前狀態：{application.get_status_display()}",
                    "current_status": application.status,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 如果還是 pending，標記為 verified
        if application.status == CertificateApplicationStatus.PENDING:
            try:
                application.mark_as_verified()
            except Exception as e:
                logger.error(
                    f"Failed to mark application {application.id} as verified: {e}",
                    exc_info=True,
                )
                return Response(
                    {"error": "更新申請狀態失敗，請稍後再試"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        # 從設置中獲取 templateId 和 certPassword
        template_id = getattr(settings, "CERTIFICATE_TEMPLATE_ID", None)
        cert_password = getattr(settings, "CERTIFICATE_PASSWORD", None)

        if not template_id:
            return Response(
                {"error": "CERTIFICATE_TEMPLATE_ID 未配置，請聯繫管理員"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        if not cert_password:
            return Response(
                {"error": "CERTIFICATE_PASSWORD 未配置，請聯繫管理員"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # 步驟 1: 獲取模板資訊
        template_data, template_status = get_template(template_id)

        if template_status != status.HTTP_200_OK or not template_data:
            if template_data:
                return Response(
                    {"error": "無法獲取模板資訊", "details": template_data},
                    status=template_status,
                )
            else:
                return Response(
                    {"error": "無法獲取模板資訊"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        # 檢查業務代碼
        business_code = template_data.get("businessCode", -1)
        if business_code != 0:
            return Response(
                {"error": "模板獲取失敗", "details": template_data},
                status=template_status,
            )

        # 步驟 2: 構建 certsData
        # 優先使用請求中的 certificateData，如果沒有則使用申請時提交的資料
        user_certificate_data = request.data.get(
            "certificateData", application.certificate_data
        )

        # 驗證 certificateData 包含 email
        if not isinstance(user_certificate_data, dict):
            return Response(
                {"error": "certificateData 必須是一個物件"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if "email" not in user_certificate_data or not user_certificate_data.get(
            "email"
        ):
            return Response(
                {"error": "certificateData 必須包含有效的 email 欄位"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        certs_data = build_certs_data_from_template(
            template_data, user_certificate_data, certificate_application=application
        )

        # 步驟 3: 構建發證請求數據
        from datetime import datetime, timezone as tz

        # 檢查是否發證到現有群組
        cert_record_group_id = application.user.cert_record_group_id
        issue_to_existing_group = cert_record_group_id is not None

        # 構建通用請求數據
        issue_request_data = {
            "certsData": certs_data,
            "certPassword": cert_password,
            "isDownloadButtonEnabled": request.data.get(
                "isDownloadButtonEnabled", True
            ),
            "skipSendingNotification": request.data.get(
                "skipSendingNotification", True
            ),
            "setVisibilityPublic": request.data.get("setVisibilityPublic", True),
            "certRecordRemark": request.data.get("certRecordRemark", ""),
            "pdfProtectionPassword": request.data.get("pdfProtectionPassword", ""),
        }

        # 處理 autoNotificationTime
        if "autoNotificationTime" in request.data:
            issue_request_data["autoNotificationTime"] = request.data[
                "autoNotificationTime"
            ]
        else:
            # 如果沒有提供，使用當前時間
            issue_request_data["autoNotificationTime"] = datetime.now(tz.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        # 處理 customEmail
        if "customEmail" in request.data:
            issue_request_data["customEmail"] = request.data["customEmail"]

        # 根據是否發證到現有群組，添加不同的參數
        if issue_to_existing_group:
            # 發證到現有群組
            issue_request_data["certRecordGroupId"] = cert_record_group_id
        else:
            # 發證到新群組
            issue_request_data["templateId"] = template_id
            # 構建證書群組名稱：裸視美手術證書-診所名稱-申請日期-申請人名稱
            if not request.data.get("name"):
                # 獲取診所名稱
                clinic_name = (
                    application.clinic.name if application.clinic else "未知診所"
                )
                # 獲取申請日期（格式：YYYYMMDD）
                create_date = (
                    application.create_time.strftime("%Y%m%d")
                    if application.create_time
                    else ""
                )
                # 獲取申請人名稱
                applicant_name = (
                    application.get_applicant_name()
                    if hasattr(application, "get_applicant_name")
                    else ""
                )
                if not applicant_name and application.user:
                    # 如果沒有 get_applicant_name 方法，手動組合
                    if application.user.first_name or application.user.last_name:
                        first_name = application.user.first_name or ""
                        last_name = application.user.last_name or ""
                        applicant_name = f"{first_name}{last_name}".strip()
                    elif application.user.username:
                        applicant_name = application.user.username
                    else:
                        applicant_name = (
                            application.user.email.split("@")[0]
                            if application.user.email
                            else "申請人"
                        )
                # 組合名稱
                issue_request_data["name"] = (
                    f"裸視美手術證書-{clinic_name}-{create_date}-{applicant_name}"
                )
            else:
                issue_request_data["name"] = request.data.get("name")

        # 步驟 4: 發證（根據是否提供 certRecordGroupId 決定發證方式）
        print(issue_request_data)

        try:
            if issue_to_existing_group:
                response_data, status_code = issue_certificates_to_existing_group(
                    issue_request_data
                )
                # 發證到現有群組時，使用提供的群組 ID
                certificate_group_id = cert_record_group_id
            else:
                response_data, status_code = issue_certificates_to_new_group(
                    issue_request_data
                )
                # 發證到新群組時，從響應中獲取群組 ID
                certificate_group_id = response_data.get("content", {}).get("id")
                application.user.cert_record_group_id = certificate_group_id
                application.user.save()
                logger.info(
                    f"Certificate group ID {certificate_group_id} saved to user {application.user.id}"
                )
        except Exception as e:
            logger.error(
                f"Failed to issue certificate for application {application.id}: {e}",
                exc_info=True,
            )
            return Response(
                {"error": "發證失敗，請稍後再試"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        if status_code not in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            return Response(
                {"error": "發證失敗", "details": response_data}, status=status_code
            )

        # 步驟 5: 從響應中提取 hash 值
        # hash 可能在 content 中，也可能在 certsData 的每個證書對象中
        certificate_hash = None
        content = response_data.get("content") or {}

        # 確保 content 是字典類型
        if not isinstance(content, dict):
            content = {}

        # 嘗試從 content 中獲取 hash
        if content and "hash" in content:
            certificate_hash = content.get("hash")
        elif (
            content
            and "certsData" in content
            and isinstance(content.get("certsData"), list)
            and len(content.get("certsData")) > 0
        ):
            # 如果 certsData 是列表，取第一個證書的 hash
            first_cert = content.get("certsData")[0]
            if isinstance(first_cert, dict) and "hash" in first_cert:
                certificate_hash = first_cert.get("hash")

        # 步驟 6: 更新申請狀態為已發證
        if certificate_group_id:
            try:
                with transaction.atomic():
                    application.mark_as_issued(certificate_group_id, certificate_hash)
                logger.info(
                    f"Certificate application {application.id} marked as issued "
                    f"with group ID {certificate_group_id}"
                    f"{f' and hash {certificate_hash}' if certificate_hash else ''}"
                )
            except Exception as e:
                logger.error(
                    f"Failed to mark application {application.id} as issued: {e}",
                    exc_info=True,
                )
                # 即使更新狀態失敗，也返回成功（證書已經發放）
                return Response(
                    {
                        "success": True,
                        "application_id": application.id,
                        "certificate_group_id": certificate_group_id,
                        "certificate_hash": certificate_hash,
                        "status": application.status,
                        "message": "證書已發放，但更新申請狀態失敗",
                        "warning": "請手動更新申請狀態為已發證",
                    },
                    status=status.HTTP_200_OK,
                )
        else:
            logger.warning(
                f"Certificate issued for application {application.id} but no group ID returned"
            )
            return Response(
                {
                    "success": True,
                    "application_id": application.id,
                    "status": application.status,
                    "message": "證書已發放，但未返回證書群組 ID",
                    "warning": "請檢查外部 API 響應",
                },
                status=status.HTTP_200_OK,
            )

        # 步驟 7: 發送證書發放通知 (先實作Email通知)
        try:
            send_certificate_issue_notification_email(application)
        except Exception as e:
            logger.error(
                f"Failed to send certificate issue notification email for application {application.id}: {e}",
                exc_info=True,
            )
            # 即使發送失敗，也繼續返回成功（證書已經發放）

        return Response(
            {
                "success": True,
                "application_id": application.id,
                "certificate_group_id": certificate_group_id,
                "certificate_hash": certificate_hash,
                "status": application.status,
                "message": "證書已成功發放",
            },
            status=status.HTTP_200_OK,
        )


def send_certificate_issue_notification_email(application):
    """
    發送證書發放通知 email 給申請人

    Args:
        application: CertificateApplication 實例（必須已發證）

    Raises:
        Exception: 如果發送失敗
    """
    # 獲取申請人 email（優先從 certificate_data，否則從 user）
    applicant_email = None
    if application.certificate_data and isinstance(application.certificate_data, dict):
        applicant_email = application.certificate_data.get("email")

    if not applicant_email and application.user:
        applicant_email = application.user.email

    if not applicant_email:
        raise ValueError(
            f"Application {application.id} does not have applicant email address"
        )

    # 構建 email 內容
    subject = "證書發放通知 - 您的證書已成功發放"

    # 獲取申請人資訊
    applicant_name = application.get_applicant_name() or "申請人"
    clinic_name = application.clinic.name if application.clinic else "診所"
    certificate_number = application.certificate_number or "待生成"
    issued_at = (
        application.issued_at.strftime("%Y-%m-%d %H:%M:%S")
        if application.issued_at
        else "剛剛"
    )

    # 構建查看證書的連結（如果有證書群組 ID）
    certificate_url = None
    if application.certificate_group_id:
        frontend_url = getattr(settings, "CLIENT_FRONTEND_URL", "http://localhost:3001")
        certificate_url = f"{frontend_url}"

    detail_item_style = "margin: 10px 0;"
    detail_items = [
        ("申請編號", f"#{application.id}"),
        ("證書序號", certificate_number),
        ("診所名稱", clinic_name),
    ]
    if application.surgeon_name:
        detail_items.append(("手術醫師", application.surgeon_name))
    if application.surgery_date:
        detail_items.append(("手術日期", application.surgery_date.strftime("%Y-%m-%d")))
    detail_items.append(("發放時間", issued_at))

    detail_items_html = "".join(
        [
            (
                f'<li style="{detail_item_style}">'
                f"<strong>{label}：</strong>{value}"
                "</li>"
            )
            for label, value in detail_items
        ]
    )

    primary_button_styles = (
        "background-color: #4CAF50; color: white; padding: 12px 30px; "
        "text-decoration: none; border-radius: 5px; display: inline-block; "
        "font-weight: bold;"
    )
    certificate_link_section = (
        '<p style="color: #666; font-size: 14px;">證書正在處理中，請稍後查看。</p>'
    )
    if certificate_url:
        certificate_link_section = f"""
            <div style="text-align: center; margin: 30px 0;">
                <a href="{certificate_url}" style="{primary_button_styles}">
                    查看證書
                </a>
            </div>
            <p style="text-align: center; color: #666; font-size: 14px;">
                或複製以下連結到瀏覽器：<br>
                <a
                    href="{certificate_url}"
                    style="color: #4CAF50; word-break: break-all;"
                >{certificate_url}</a>
            </p>
            """

    # 使用 HTML 模板
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2
                style="
                    color: #4CAF50;
                    border-bottom: 3px solid #4CAF50;
                    padding-bottom: 10px;
                "
            >證書發放通知</h2>
            <p>親愛的 {applicant_name}，</p>
            <p>恭喜！您的證書已成功發放。</p>

            <div
                style="
                    background-color: #f9f9f9;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                "
            >
                <h3 style="margin-top: 0; color: #333;">證書資訊</h3>
                <ul style="list-style: none; padding: 0;">
                    {detail_items_html}
                </ul>
            </div>

            {certificate_link_section}

            <div
                style="
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    color: #666;
                    font-size: 14px;
                "
            >
                <p>如有任何疑問，請聯繫相關診所或系統管理員。</p>
                <p style="margin-top: 20px;"><small>此為系統自動發送，請勿回覆此郵件。</small></p>
            </div>
        </div>
    </body>
    </html>
    """

    details_text_lines = [
        "證書資訊：",
        f"- 申請編號：#{application.id}",
        f"- 證書序號：{certificate_number}",
        f"- 診所名稱：{clinic_name}",
    ]
    if application.surgeon_name:
        details_text_lines.append(f"- 手術醫師：{application.surgeon_name}")
    if application.surgery_date:
        details_text_lines.append(
            f"- 手術日期：{application.surgery_date.strftime('%Y-%m-%d')}"
        )
    details_text_lines.append(f"- 發放時間：{issued_at}")

    certificate_text = (
        "證書正在處理中，請稍後查看。"
        if not certificate_url
        else f"查看證書：{certificate_url}"
    )

    # 純文字版本（用於不支持 HTML 的 email 客戶端）
    plain_message = "\n".join(
        [
            "證書發放通知",
            "",
            f"親愛的 {applicant_name}，",
            "",
            "恭喜！您的證書已成功發放。",
            "",
            *details_text_lines,
            "",
            certificate_text,
            "",
            "如有任何疑問，請聯繫相關診所或系統管理員。",
            "",
            "此為系統自動發送，請勿回覆此郵件。",
        ]
    )

    # 發送 email（使用密件副本保護個資）
    from django.core.mail import EmailMultiAlternatives

    email_msg = EmailMultiAlternatives(
        subject=subject,
        body=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[],  # 使用空列表，避免在 To 欄位顯示收件人
        bcc=[applicant_email],  # 使用密件副本保護個資
    )
    email_msg.attach_alternative(html_message, "text/html")
    email_msg.send(fail_silently=False)

    logger.info(
        f"Certificate issue notification email sent successfully to {applicant_email} "
        f"for application {application.id} (user: {application.user.id if application.user else 'N/A'}, "
        f"clinic: {application.clinic.id if application.clinic else 'N/A'})"
    )


class DoctorViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing doctors in clinics.

    Provides CRUD operations for doctors:
    - List: GET /api/doctors/ (with optional clinic_id filter)
    - Create: POST /api/doctors/
    - Retrieve: GET /api/doctors/{id}/
    - Update: PUT/PATCH /api/doctors/{id}/
    - Delete: DELETE /api/doctors/{id}/
    """

    queryset = (
        Doctor.objects.select_related("clinic", "user").all().order_by("-create_time")
    )
    serializer_class = DoctorSerializer
    permission_classes = [IsAuthenticated, IsAdminRolePermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    filterset_fields = ["clinic", "is_active", "user"]
    ordering_fields = ["name", "create_time", "is_active", "specialty", "title"]
    ordering = ["-create_time"]
    search_fields = ["name", "email", "phone", "license_number", "specialty", "title"]
    pagination_class = StandardResultsSetPagination

    @extend_schema(
        tags=["Clinic Doctors"],
        summary="List doctors",
        description="""
        獲取醫生列表。

        **查詢參數：**
        - `clinic`: 診所 ID（可選，用於篩選特定診所的醫生）
        - `is_active`: 是否啟用（可選，true/false）
        - `user`: 用戶 ID（可選，用於篩選特定用戶的醫生資料）
        - `search`: 搜尋關鍵字（可選，會搜尋姓名、email、電話、執照號碼、專科、職稱）
        - `ordering`: 排序欄位（可選，如：name, -create_time, is_active）
        """,
        parameters=[
            OpenApiParameter(
                name="clinic",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description="診所 ID（用於篩選特定診所的醫生）",
            ),
            OpenApiParameter(
                name="is_active",
                type=bool,
                location=OpenApiParameter.QUERY,
                required=False,
                description="是否啟用（true/false）",
            ),
            OpenApiParameter(
                name="search",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="搜尋關鍵字（會搜尋姓名、email、電話、執照號碼、專科、職稱）",
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        """獲取醫生列表"""
        return super().list(request, *args, **kwargs)

    @extend_schema(
        tags=["Clinic Doctors"],
        summary="Create doctor",
        description="""
        創建新醫生。

        **必填欄位：**
        - `clinic_id`: 診所 ID
        - `name`: 醫生姓名

        **可選欄位：**
        - `user_id`: 用戶 ID（如果醫生也是系統用戶）
        - `email`: 電子郵件
        - `phone`: 電話
        - `license_number`: 執業執照號碼
        - `specialty`: 專科
        - `title`: 職稱
        - `is_active`: 是否啟用（默認為 true）
        - `notes`: 備註
        """,
        examples=[
            OpenApiExample(
                "Create Doctor Request",
                value={
                    "clinic_id": 1,
                    "name": "王醫師",
                    "email": "doctor@example.com",
                    "phone": "0912345678",
                    "license_number": "DOC123456",
                    "specialty": "內科",
                    "title": "主任醫師",
                    "is_active": True,
                    "notes": "資深內科醫師",
                },
                request_only=True,
            ),
        ],
    )
    def create(self, request, *args, **kwargs):
        """創建醫生"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # 驗證必填欄位
        if "clinic_id" not in serializer.validated_data:
            return Response(
                {"error": "clinic_id 是必填欄位"}, status=status.HTTP_400_BAD_REQUEST
            )

        # 獲取診所和用戶（已在 serializer 中驗證）
        clinic_id = serializer.validated_data.pop("clinic_id")
        clinic = Clinic.objects.get(id=clinic_id)

        user_id = serializer.validated_data.pop("user_id", None)
        user = User.objects.get(id=user_id) if user_id else None

        # 創建醫生
        serializer.save(
            clinic=clinic,
            user=user,
            create_user=request.user if request.user.is_authenticated else None,
        )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @extend_schema(
        tags=["Clinic Doctors"],
        summary="Retrieve doctor",
        description="獲取醫生詳細資訊。",
    )
    def retrieve(self, request, *args, **kwargs):
        """獲取醫生詳細資訊"""
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        tags=["Clinic Doctors"],
        summary="Update doctor",
        description="""
        更新醫生資訊。

        使用 PUT 進行完整更新，或使用 PATCH 進行部分更新。
        """,
        examples=[
            OpenApiExample(
                "Update Doctor Request (PATCH)",
                value={
                    "name": "王醫師（已更新）",
                    "specialty": "心臟內科",
                    "is_active": True,
                },
                request_only=True,
            ),
        ],
    )
    def update(self, request, *args, **kwargs):
        """更新醫生資訊"""
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # 如果更新了 clinic_id，獲取診所對象（已在 serializer 中驗證）
        if "clinic_id" in serializer.validated_data:
            clinic_id = serializer.validated_data.pop("clinic_id")
            clinic = Clinic.objects.get(id=clinic_id)
            serializer.validated_data["clinic"] = clinic

        # 如果更新了 user_id，獲取用戶對象（已在 serializer 中驗證）
        if "user_id" in serializer.validated_data:
            user_id = serializer.validated_data.pop("user_id")
            user = User.objects.get(id=user_id) if user_id else None
            serializer.validated_data["user"] = user

        self.perform_update(serializer)

        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    @extend_schema(
        tags=["Clinic Doctors"],
        summary="Partial update doctor",
        description="部分更新醫生資訊（PATCH）。",
    )
    def partial_update(self, request, *args, **kwargs):
        """部分更新醫生資訊"""
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    @extend_schema(
        tags=["Clinic Doctors"], summary="Delete doctor", description="刪除醫生。"
    )
    def destroy(self, request, *args, **kwargs):
        """刪除醫生"""
        return super().destroy(request, *args, **kwargs)


class GetCertificateView(APIView):
    """
    API endpoint to get certificate details.

    GET /api/certificates/get-certificate/
    This endpoint retrieves certificate details by id or hash.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Certificates"],
        summary="Get certificate details",
        description="""
        獲取證書詳細資料。

        **流程說明：**
        1. 檢查用戶是否有 cert_record_group_id（表示用戶已有證書群組）
        2. 接收證書 id 或 hash 參數（至少需要提供其中一個）
        3. 調用外部 API 獲取證書詳細資料
        4. 返回證書資訊

        **必填參數（至少填寫其中一個）：**
        - `id`: 證書 ID（number）
        - `hash`: 證書 hash（string）

        **權限說明：**
        - 用戶必須已登入
        - 用戶必須有 cert_record_group_id（表示用戶已有證書群組）

        **返回內容：**
        - `id`: 證書 id
        - `certName`: 證書名字
        - `institution`: 證書機構
        - `issueTime`: 發證時間
        - `blockchainHash`: 區塊鏈 Hash
        - `visibility`: 公開或是不公開
        - `expiredTime`: 過期時間
        - `pdfld`: pdf 檔案 ID
        - `datas`: 此證書包含的資料內容
        """,
        parameters=[
            OpenApiParameter(
                name="id",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description="證書 ID",
            ),
            OpenApiParameter(
                name="hash",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description="證書 hash",
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="成功獲取證書資料",
                response=inline_serializer(
                    name="GetCertificateSuccessResponse",
                    fields={
                        "success": serializers.BooleanField(help_text="是否成功"),
                        "code": serializers.IntegerField(help_text="HTTP 狀態碼"),
                        "businessCode": serializers.IntegerField(help_text="業務代碼"),
                        "content": serializers.DictField(help_text="證書內容"),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="請求參數錯誤",
                response=inline_serializer(
                    name="GetCertificateErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            403: OpenApiResponse(
                description="權限不足或沒有證書群組",
                response=inline_serializer(
                    name="GetCertificateForbiddenResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            404: OpenApiResponse(
                description="證書不存在",
                response=inline_serializer(
                    name="GetCertificateNotFoundResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            500: OpenApiResponse(
                description="內部服務器錯誤或外部 API 調用失敗",
                response=inline_serializer(
                    name="GetCertificateServerErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
        },
    )
    def get(self, request):
        """
        獲取證書詳細資料
        """
        user = request.user

        # 檢查用戶是否有 cert_record_group_id
        if not user.cert_record_group_id:
            return Response(
                {"error": "您尚未有證書群組，無法獲取證書資料"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 獲取請求參數
        cert_id = request.query_params.get("id")
        cert_hash = request.query_params.get("hash")

        # 轉換 cert_id 為整數（如果提供）
        if cert_id:
            try:
                cert_id = int(cert_id)
            except ValueError:
                return Response(
                    {"error": "id 參數必須是有效的整數"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # 調用外部 API 獲取證書資料
        response_data, status_code = get_certificate(
            cert_id=cert_id, cert_hash=cert_hash
        )

        return Response(response_data, status=status_code)


class GetCertificatePdfView(APIView):
    """
    API endpoint to get certificate PDF URL.

    GET /api/certificates/get-pdf/
    This endpoint retrieves certificate PDF URL by pdf_id.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Certificates"],
        summary="Get certificate PDF URL",
        description="""
        獲取證書 PDF 檔案 URL。

        **流程說明：**
        1. 檢查用戶是否有 cert_record_group_id（表示用戶已有證書群組）
        2. 接收 pdf_id 參數
        3. 調用外部 API 獲取 PDF URL（會重新導向至 GCS link，連結有效時長為3天）
        4. 返回 PDF URL

        **必填參數：**
        - `id`: PDF 檔案 ID（string，可以從證書資料取得）

        **權限說明：**
        - 用戶必須已登入
        - 用戶必須有 cert_record_group_id（表示用戶已有證書群組）

        **返回內容：**
        - 重新導向至 GCS link（連結有效時長為3天）
        """,
        parameters=[
            OpenApiParameter(
                name="id",
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description="PDF 檔案 ID（可以從證書資料取得）",
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="成功獲取 PDF URL",
                response=inline_serializer(
                    name="GetPdfUrlSuccessResponse",
                    fields={
                        "url": serializers.CharField(
                            help_text="PDF URL（GCS link，有效時長為3天）"
                        )
                    },
                ),
            ),
            400: OpenApiResponse(
                description="請求參數錯誤",
                response=inline_serializer(
                    name="GetPdfUrlErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            403: OpenApiResponse(
                description="權限不足或沒有證書群組",
                response=inline_serializer(
                    name="GetPdfUrlForbiddenResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            404: OpenApiResponse(
                description="PDF 檔案不存在",
                response=inline_serializer(
                    name="GetPdfUrlNotFoundResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
            500: OpenApiResponse(
                description="內部服務器錯誤或外部 API 調用失敗",
                response=inline_serializer(
                    name="GetPdfUrlServerErrorResponse",
                    fields={"error": serializers.CharField(help_text="錯誤訊息")},
                ),
            ),
        },
    )
    def get(self, request):
        """
        獲取證書 PDF URL
        """
        user = request.user

        # 檢查用戶是否有 cert_record_group_id
        if not user.cert_record_group_id:
            return Response(
                {"error": "您尚未有證書群組，無法獲取 PDF 檔案"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 獲取請求參數
        pdf_id = request.query_params.get("id")

        if not pdf_id:
            return Response(
                {"error": "id 參數是必填的"}, status=status.HTTP_400_BAD_REQUEST
            )

        # 調用外部 API 獲取 PDF URL
        pdf_url, status_code = get_pdf_url(pdf_id=pdf_id)

        # 如果成功獲取 URL，返回 URL
        if status_code == status.HTTP_200_OK and isinstance(pdf_url, str):
            return Response({"url": pdf_url}, status=status.HTTP_200_OK)

        # 否則返回錯誤
        return Response(pdf_url, status=status_code)
