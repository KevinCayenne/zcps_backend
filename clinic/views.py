"""
Views for Clinic and Certificate Application.
"""

import logging
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.utils.html import strip_tags
from rest_framework import status, serializers, viewsets, filters
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import (
    extend_schema, OpenApiResponse, OpenApiExample, OpenApiParameter, inline_serializer
)

from users.models import User
from clinic.models import Clinic, CertificateApplication, Doctor
from clinic.enums import CertificateApplicationStatus
from clinic.serializers import (
    CertificateApplicationCreateSerializer,
    CertificateApplicationSerializer,
    CertificateVerificationSerializer,
    ClinicSerializer,
    DoctorSerializer
)
from config.paginator import StandardResultsSetPagination

logger = logging.getLogger(__name__)


class SubmitCertificateApplicationView(APIView):
    """
    API endpoint to submit a certificate application.
    
    POST /api/certificates/submit-application/
    This endpoint receives form data and clinic information, generates a verification token,
    and sends a verification email to the clinic.
    """
    
    permission_classes = [AllowAny]
    
    @extend_schema(
        tags=['Certificates'],
        summary='Submit certificate application',
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
                'Request Example',
                value={
                    "user_id": 1,
                    "clinic_id": 1,
                    "certificate_data": {
                        "email": "member@example.com",
                        "tx-101": "獎狀",
                        "tx-103": "張三"
                    }
                },
                request_only=True,
            ),
        ],
        responses={
            201: OpenApiResponse(
                description='申請提交成功',
                response=inline_serializer(
                    name='SubmitApplicationResponse',
                    fields={
                        'application_id': serializers.IntegerField(help_text='申請 ID'),
                        'status': serializers.CharField(help_text='申請狀態'),
                        'message': serializers.CharField(help_text='成功訊息'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='請求資料錯誤',
                response=inline_serializer(
                    name='SubmitApplicationErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息'),
                        'details': serializers.DictField(required=False, help_text='詳細錯誤資訊')
                    }
                )
            ),
            404: OpenApiResponse(
                description='用戶或診所不存在',
                response=inline_serializer(
                    name='SubmitApplicationNotFoundResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
        }
    )
    def post(self, request):
        """
        提交證書申請
        """
        serializer = CertificateApplicationCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': '請求資料錯誤', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        data = serializer.validated_data
        
        # 驗證用戶是否存在
        try:
            user = User.objects.get(id=data['user_id'])
        except User.DoesNotExist:
            return Response(
                {'error': '用戶不存在'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # 驗證診所是否存在
        try:
            clinic = Clinic.objects.get(id=data['clinic_id'])
        except Clinic.DoesNotExist:
            return Response(
                {'error': '診所不存在'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # 檢查診所是否有 email
        if not clinic.email:
            return Response(
                {'error': '診所未設置電子郵件地址'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 驗證 certificate_data 包含 email
        certificate_data = data.get('certificate_data', {})
        if not isinstance(certificate_data, dict):
            return Response(
                {'error': 'certificate_data 必須是一個物件'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if 'email' not in certificate_data or not certificate_data.get('email'):
            return Response(
                {'error': 'certificate_data 必須包含有效的 email 欄位'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 使用事務確保數據一致性
        try:
            with transaction.atomic():
                # 創建證書申請
                application = CertificateApplication.objects.create(
                    user=user,
                    clinic=clinic,
                    certificate_data=certificate_data,
                    create_user=request.user if request.user.is_authenticated else None
                )
                
                # 生成驗證 token
                token = application.generate_verification_token()
                application.save()
        except Exception as e:
            logger.error(f"Failed to create certificate application: {e}", exc_info=True)
            return Response(
                {'error': '創建證書申請失敗，請稍後再試'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # 發送驗證 email（在事務外，避免影響數據保存）
        try:
            self._send_verification_email(application, token)
        except Exception as e:
            logger.error(
                f"Failed to send verification email for application {application.id}: {e}",
                exc_info=True
            )
            # 即使發送失敗，也返回成功（可以稍後重試或手動發送）
        
        return Response(
            {
                'application_id': application.id,
                'status': application.status,
                'message': '申請已提交，驗證 email 已發送到診所'
            },
            status=status.HTTP_201_CREATED
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
            raise ValueError(f"Clinic {application.clinic.id} does not have an email address")
        
        frontend_url = getattr(settings, 'CLIENT_FRONTEND_URL', 'http://localhost:3000')
        
        # 構建驗證連結
        verification_url = f"{frontend_url}/certificate/verify?token={token}"
        
        # 構建 email 內容
        subject = '證書申請驗證 - 請確認證書發放'
        
        # 從用戶獲取申請人資訊
        applicant_name = application.get_applicant_name()
        applicant_email = application.get_applicant_email()
        applicant_phone = application.get_applicant_phone()
        
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
                {f'<li><strong>申請人電話：</strong>{applicant_phone}</li>' if applicant_phone else ''}
            </ul>
            <p>請點擊以下連結確認並完成證書發放：</p>
            <p><a href="{verification_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">確認並發放證書</a></p>
            <p>或複製以下連結到瀏覽器：</p>
            <p>{verification_url}</p>
            <p><small>此連結將在 7 天後過期</small></p>
            <hr>
            <p><small>此為系統自動發送，請勿回覆此郵件。</small></p>
        </body>
        </html>
        """
        
        plain_message = strip_tags(html_message)
        
        # 發送 email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[application.clinic.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(
            f"Verification email sent successfully to {application.clinic.email} "
            f"for application {application.id} (user: {application.user.id}, clinic: {application.clinic.id})"
        )


class VerifyCertificateTokenView(APIView):
    """
    API endpoint to verify certificate application token.
    
    GET /api/certificates/verify-token/?token=<token>
    This endpoint verifies the token and returns application information.
    """
    
    permission_classes = [AllowAny]
    
    @extend_schema(
        tags=['Certificates'],
        summary='Verify certificate application token',
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
                name='token',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='驗證 token'
            )
        ],
        responses={
            200: OpenApiResponse(
                description='Token 驗證成功',
                response=inline_serializer(
                    name='VerifyTokenResponse',
                    fields={
                        'valid': serializers.BooleanField(help_text='Token 是否有效'),
                        'application': CertificateApplicationSerializer(),
                        'message': serializers.CharField(help_text='狀態訊息'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Token 無效或已過期',
                response=inline_serializer(
                    name='VerifyTokenErrorResponse',
                    fields={
                        'valid': serializers.BooleanField(help_text='Token 是否有效'),
                        'error': serializers.CharField(help_text='錯誤訊息'),
                        'status': serializers.CharField(required=False, help_text='申請狀態')
                    }
                )
            ),
        }
    )
    def get(self, request):
        """
        驗證 token
        """
        token = request.query_params.get('token')
        
        if not token:
            return Response(
                {'error': '缺少 token 參數'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            application = CertificateApplication.objects.get(verification_token=token)
        except CertificateApplication.DoesNotExist:
            return Response(
                {'error': '無效的 token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 檢查 token 是否有效
        if not application.is_token_valid():
            return Response(
                {
                    'valid': False,
                    'error': 'Token 已過期或已被使用',
                    'status': application.status
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 標記為已驗證（如果還是 pending 狀態）
        if application.status == CertificateApplicationStatus.PENDING:
            try:
                application.mark_as_verified()
            except Exception as e:
                logger.error(f"Failed to mark application {application.id} as verified: {e}", exc_info=True)
                return Response(
                    {'error': '更新申請狀態失敗，請稍後再試'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        serializer = CertificateApplicationSerializer(application)
        
        return Response(
            {
                'valid': True,
                'application': serializer.data,
                'message': 'Token 驗證成功'
            },
            status=status.HTTP_200_OK
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
    queryset = Doctor.objects.select_related('clinic', 'user').all().order_by('-create_time')
    serializer_class = DoctorSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
        filters.SearchFilter,
    ]
    filterset_fields = ['clinic', 'is_active', 'user']
    ordering_fields = ['name', 'create_time', 'is_active', 'specialty', 'title']
    ordering = ['-create_time']
    search_fields = ['name', 'email', 'phone', 'license_number', 'specialty', 'title']
    pagination_class = StandardResultsSetPagination
    
    @extend_schema(
        tags=['Clinic Doctors'],
        summary='List doctors',
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
                name='clinic',
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description='診所 ID（用於篩選特定診所的醫生）'
            ),
            OpenApiParameter(
                name='is_active',
                type=bool,
                location=OpenApiParameter.QUERY,
                required=False,
                description='是否啟用（true/false）'
            ),
            OpenApiParameter(
                name='search',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='搜尋關鍵字（會搜尋姓名、email、電話、執照號碼、專科、職稱）'
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        """獲取醫生列表"""
        return super().list(request, *args, **kwargs)
    
    @extend_schema(
        tags=['Clinic Doctors'],
        summary='Create doctor',
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
                'Create Doctor Request',
                value={
                    "clinic_id": 1,
                    "name": "王醫師",
                    "email": "doctor@example.com",
                    "phone": "0912345678",
                    "license_number": "DOC123456",
                    "specialty": "內科",
                    "title": "主任醫師",
                    "is_active": True,
                    "notes": "資深內科醫師"
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
        if 'clinic_id' not in serializer.validated_data:
            return Response(
                {'error': 'clinic_id 是必填欄位'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 獲取診所和用戶（已在 serializer 中驗證）
        clinic_id = serializer.validated_data.pop('clinic_id')
        clinic = Clinic.objects.get(id=clinic_id)
        
        user_id = serializer.validated_data.pop('user_id', None)
        user = User.objects.get(id=user_id) if user_id else None
        
        # 創建醫生
        doctor = serializer.save(
            clinic=clinic,
            user=user,
            create_user=request.user if request.user.is_authenticated else None
        )
        
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )
    
    @extend_schema(
        tags=['Clinic Doctors'],
        summary='Retrieve doctor',
        description="獲取醫生詳細資訊。"
    )
    def retrieve(self, request, *args, **kwargs):
        """獲取醫生詳細資訊"""
        return super().retrieve(request, *args, **kwargs)
    
    @extend_schema(
        tags=['Clinic Doctors'],
        summary='Update doctor',
        description="""
        更新醫生資訊。
        
        使用 PUT 進行完整更新，或使用 PATCH 進行部分更新。
        """,
        examples=[
            OpenApiExample(
                'Update Doctor Request (PATCH)',
                value={
                    "name": "王醫師（已更新）",
                    "specialty": "心臟內科",
                    "is_active": True
                },
                request_only=True,
            ),
        ],
    )
    def update(self, request, *args, **kwargs):
        """更新醫生資訊"""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        
        # 如果更新了 clinic_id，獲取診所對象（已在 serializer 中驗證）
        if 'clinic_id' in serializer.validated_data:
            clinic_id = serializer.validated_data.pop('clinic_id')
            clinic = Clinic.objects.get(id=clinic_id)
            serializer.validated_data['clinic'] = clinic
        
        # 如果更新了 user_id，獲取用戶對象（已在 serializer 中驗證）
        if 'user_id' in serializer.validated_data:
            user_id = serializer.validated_data.pop('user_id')
            user = User.objects.get(id=user_id) if user_id else None
            serializer.validated_data['user'] = user
        
        self.perform_update(serializer)
        
        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}
        
        return Response(serializer.data)
    
    @extend_schema(
        tags=['Clinic Doctors'],
        summary='Partial update doctor',
        description="部分更新醫生資訊（PATCH）。"
    )
    def partial_update(self, request, *args, **kwargs):
        """部分更新醫生資訊"""
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)
    
    @extend_schema(
        tags=['Clinic Doctors'],
        summary='Delete doctor',
        description="刪除醫生。"
    )
    def destroy(self, request, *args, **kwargs):
        """刪除醫生"""
        return super().destroy(request, *args, **kwargs)
