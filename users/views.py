"""
Views for user authentication and profile management.

Provides custom views for logout functionality with token blacklisting,
and custom password management views with JWT token blacklisting.
"""
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, OpenApiParameter, inline_serializer
from djoser.views import UserViewSet
from django.conf import settings
from .serializers import LogoutSerializer
from .utils import blacklist_user_tokens
from .models import User, EmailVerificationOTP
from .permissions import IsStaffRolePermission, IsAdminRolePermission
from config.paginator import StandardResultsSetPagination
from rest_framework import viewsets, filters
from .serializers import UserSerializer, ClientUserSerializer
from .filters import UserFilterSet
from users.enums import UserRole

# 導入診所相關模組
try:
    from clinic.models import ClinicUserPermission, Clinic
except ImportError:
    ClinicUserPermission = None
    Clinic = None


class SendRegistrationOTPView(APIView):
    """
    API endpoint to send OTP for email verification before registration.
    
    POST /auth/users/send-registration-otp/
    This endpoint sends a 6-digit OTP to the provided email address.
    """
    
    permission_classes = []  # 公開訪問，不需要認證
    
    @extend_schema(
        tags=['User Management'],
        summary='Send registration OTP (Public)',
        description="""
        發送註冊用的 OTP 驗證碼到指定的 email。
        
        **流程說明：**
        1. 用戶輸入 email
        2. 調用此 API 發送 OTP
        3. 系統發送 6 位數驗證碼到 email
        4. 用戶收到驗證碼後，調用驗證 API 確認 email
        
        **使用場景：**
        - 註冊頁面，用戶輸入 email 後點擊「發送驗證碼」
        - 確保 email 地址有效且用戶可以接收郵件
        - 防止使用無效或他人的 email 註冊
        
        **重要事項：**
        - OTP 有效期為 10 分鐘（可配置）
        - 每個 email 最多只能有 1 個未使用的 OTP
        - 如果發送新的 OTP，舊的會被標記為已使用
        - 驗證失敗超過 5 次需重新發送
        
        **安全考量：**
        - 即使 email 不存在，也返回成功（防止 email 枚舉攻擊）
        - 有發送頻率限制（建議前端實現防抖）
        """,
        request=inline_serializer(
            name='SendRegistrationOTPRequest',
            fields={
                'email': serializers.EmailField(help_text='要驗證的 email 地址'),
            }
        ),
        examples=[
            OpenApiExample(
                'Send OTP Request',
                value={'email': 'user@example.com'},
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='OTP 已發送（即使 email 不存在也返回成功，防止枚舉攻擊）',
                response=inline_serializer(
                    name='SendRegistrationOTPSuccessResponse',
                    fields={
                        'message': serializers.CharField(help_text='成功訊息'),
                        'expires_at': serializers.DateTimeField(help_text='OTP 過期時間'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad Request - email 格式無效',
                response=inline_serializer(
                    name='SendRegistrationOTPErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息'),
                    }
                )
            ),
            429: OpenApiResponse(
                description='Too Many Requests - 發送頻率過高',
                response=inline_serializer(
                    name='SendRegistrationOTPRateLimitResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息'),
                    }
                )
            ),
        }
    )
    def post(self, request):
        """
        發送註冊用的 OTP 驗證碼
        """
        email = request.data.get('email', '').strip()
        
        if not email:
            return Response(
                {'error': 'email 參數是必填的'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 驗證 email 格式
        from django.core.validators import validate_email
        from django.core.exceptions import ValidationError
        
        try:
            validate_email(email)
        except ValidationError:
            return Response(
                {'error': 'email 格式無效'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 檢查 email 是否已被使用（如果已註冊，不需要發送 OTP）
        if User.objects.filter(email__iexact=email).exists():
            # 即使 email 已被使用，也返回成功（防止枚舉攻擊）
            # 但在驗證 OTP 時會檢查
            return Response(
                {
                    'message': '如果此 email 尚未註冊，驗證碼已發送到您的 email',
                    'expires_at': None
                },
                status=status.HTTP_200_OK
            )
        
        # 檢查發送頻率（防止濫用）
        from django.utils import timezone
        from datetime import timedelta
        
        recent_otp = EmailVerificationOTP.objects.filter(
            email__iexact=email,
            created_at__gte=timezone.now() - timedelta(minutes=1)
        ).first()
        
        if recent_otp:
            return Response(
                {'error': '請稍候再試，發送頻率過高'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # 生成 6 位數驗證碼
        import secrets
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # 設置過期時間（10 分鐘）
        expires_at = timezone.now() + timedelta(minutes=10)
        
        # 將舊的未使用 OTP 標記為已使用
        EmailVerificationOTP.objects.filter(
            email__iexact=email,
            is_used=False
        ).update(is_used=True)
        
        # 創建新的 OTP
        otp = EmailVerificationOTP.objects.create(
            email=email,
            code=code,
            expires_at=expires_at
        )
        
        # 發送 OTP 到 email
        try:
            from django.core.mail import EmailMultiAlternatives
            from django.conf import settings
            
            subject = '您的註冊驗證碼'
            message = f"""親愛的用戶，

您的註冊驗證碼是：

{code}

此驗證碼將在 10 分鐘後過期。

如果您沒有申請註冊，請忽略此郵件。

謝謝！
"""
            
            # 使用 EmailMultiAlternatives 以支持 BCC
            email_msg = EmailMultiAlternatives(
                subject=subject,
                body=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[],  # 使用空列表，避免在 To 欄位顯示收件人
                bcc=[email],  # 使用密件副本保護個資
            )
            email_msg.send(fail_silently=False)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send OTP email to {email}: {e}")
            # 即使發送失敗，也返回成功（防止枚舉攻擊）
        
        return Response(
            {
                'message': '驗證碼已發送到您的 email',
                'expires_at': expires_at
            },
            status=status.HTTP_200_OK
        )


class VerifyRegistrationOTPView(APIView):
    """
    API endpoint to verify OTP for email verification before registration.
    
    POST /auth/users/verify-registration-otp/
    This endpoint verifies the OTP code sent to the email.
    """
    
    permission_classes = []  # 公開訪問，不需要認證
    
    @extend_schema(
        tags=['User Management'],
        summary='Verify registration OTP (Public)',
        description="""
        驗證註冊用的 OTP 驗證碼。
        
        **流程說明：**
        1. 用戶收到 OTP 驗證碼
        2. 輸入驗證碼並調用此 API
        3. 系統驗證 OTP 是否正確
        4. 驗證成功後，可以進行註冊
        
        **驗證規則：**
        - OTP 必須在 10 分鐘內使用
        - OTP 只能使用一次
        - 驗證失敗超過 5 次需重新發送
        - email 必須尚未註冊
        
        **返回結果：**
        - `verified`: true 表示驗證成功
        - `verified`: false 表示驗證失敗
        - `token`: 驗證成功後返回的臨時 token（可選，用於後續註冊時驗證）
        
        **使用場景：**
        - 註冊頁面，用戶輸入 OTP 後點擊「驗證」
        - 驗證成功後，允許用戶繼續註冊流程
        """,
        request=inline_serializer(
            name='VerifyRegistrationOTPRequest',
            fields={
                'email': serializers.EmailField(help_text='要驗證的 email 地址'),
                'code': serializers.CharField(help_text='6 位數驗證碼'),
            }
        ),
        examples=[
            OpenApiExample(
                'Verify OTP Request',
                value={
                    'email': 'user@example.com',
                    'code': '123456'
                },
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='OTP 驗證結果',
                response=inline_serializer(
                    name='VerifyRegistrationOTPSuccessResponse',
                    fields={
                        'verified': serializers.BooleanField(help_text='是否驗證成功'),
                        'message': serializers.CharField(help_text='狀態訊息'),
                        'token': serializers.CharField(required=False, help_text='驗證成功後的臨時 token（可選）'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad Request - 參數錯誤或驗證失敗',
                response=inline_serializer(
                    name='VerifyRegistrationOTPErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息'),
                    }
                )
            ),
        }
    )
    def post(self, request):
        """
        驗證註冊用的 OTP 驗證碼
        """
        email = request.data.get('email', '').strip()
        code = request.data.get('code', '').strip()
        
        if not email or not code:
            return Response(
                {'error': 'email 和 code 參數都是必填的'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 驗證 email 格式
        from django.core.validators import validate_email
        from django.core.exceptions import ValidationError
        
        try:
            validate_email(email)
        except ValidationError:
            return Response(
                {'error': 'email 格式無效'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 檢查 email 是否已被註冊
        if User.objects.filter(email__iexact=email).exists():
            return Response(
                {
                    'verified': False,
                    'error': '此 email 已被註冊'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 查找最新的未使用 OTP
        otp = EmailVerificationOTP.objects.filter(
            email__iexact=email,
            is_used=False
        ).order_by('-created_at').first()
        
        if not otp:
            return Response(
                {
                    'verified': False,
                    'error': '未找到有效的驗證碼，請重新發送'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 檢查 OTP 是否有效
        if not otp.is_valid():
            if otp.failed_attempts >= 5:
                return Response(
                    {
                        'verified': False,
                        'error': '驗證失敗次數過多，請重新發送驗證碼'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                return Response(
                    {
                        'verified': False,
                        'error': '驗證碼已過期，請重新發送'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # 驗證 code 是否正確
        if otp.code != code:
            # 增加失敗次數
            otp.failed_attempts += 1
            otp.save(update_fields=['failed_attempts'])
            
            return Response(
                {
                    'verified': False,
                    'error': f'驗證碼錯誤，還剩 {5 - otp.failed_attempts} 次機會'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 驗證成功，標記為已使用
        otp.is_used = True
        otp.save(update_fields=['is_used'])
        
        # 生成臨時驗證 token（可選，用於後續註冊時驗證）
        # 這裡可以使用 JWT 或其他方式生成 token
        import secrets
        verification_token = secrets.token_urlsafe(32)
        
        # 可以將 token 存儲在 session 或 cache 中
        # 這裡簡化處理，直接返回成功
        
        return Response(
            {
                'verified': True,
                'message': 'Email 驗證成功',
                'token': verification_token  # 可選，用於後續註冊驗證
            },
            status=status.HTTP_200_OK
        )


class VerifyEmailView(APIView):
    """
    API endpoint to verify email availability before registration.
    
    GET /auth/users/verify-email/?email=<email>
    This endpoint checks if an email is available for registration.
    """
    
    permission_classes = []  # 公開訪問，不需要認證
    
    @extend_schema(
        tags=['User Management'],
        summary='Verify email availability (Public)',
        description="""
        驗證 email 是否可用於註冊。
        
        **用途：**
        - 在註冊頁面實時檢查 email 是否已被使用
        - 提供即時反饋，改善用戶體驗
        - 避免用戶填寫完整表單後才發現 email 已被使用
        
        **返回結果：**
        - `available`: true 表示 email 可用（未被使用）
        - `available`: false 表示 email 已被使用
        - `email`: 驗證的 email 地址
        
        **使用場景：**
        - 用戶在註冊表單中輸入 email 時
        - 前端可以實時調用此 API 檢查
        - 如果 email 已被使用，可以立即提示用戶
        
        **注意事項：**
        - 此 API 是公開的，不需要認證
        - 只檢查 email 是否存在，不驗證 email 格式
        - 建議在前端也進行 email 格式驗證
        """,
        parameters=[
            OpenApiParameter(
                name='email',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='要驗證的 email 地址'
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='Email 驗證結果',
                response=inline_serializer(
                    name='EmailVerificationResponse',
                    fields={
                        'email': serializers.EmailField(help_text='驗證的 email 地址'),
                        'available': serializers.BooleanField(help_text='email 是否可用（true=可用，false=已被使用）'),
                        'message': serializers.CharField(help_text='狀態訊息'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad Request - 缺少 email 參數或 email 格式無效',
                response=inline_serializer(
                    name='EmailVerificationErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息'),
                    }
                )
            ),
        }
    )
    def get(self, request):
        """
        驗證 email 是否可用於註冊
        """
        email = request.query_params.get('email', '').strip()
        
        if not email:
            return Response(
                {'error': 'email 參數是必填的'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 驗證 email 格式
        from django.core.validators import validate_email
        from django.core.exceptions import ValidationError
        
        try:
            validate_email(email)
        except ValidationError:
            return Response(
                {'error': 'email 格式無效'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 檢查 email 是否已被使用
        email_exists = User.objects.filter(email__iexact=email).exists()
        
        return Response(
            {
                'email': email,
                'available': not email_exists,
                'message': '此 email 可用' if not email_exists else '此 email 已被使用'
            },
            status=status.HTTP_200_OK
        )


class LogoutView(APIView):
    """
    Custom logout view that blacklists the refresh token.

    POST /auth/logout/
    Requires authentication and accepts refresh token in request body.
    Blacklists the token to prevent further use.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    @extend_schema(
        tags=['Authentication'],
        summary='Logout and blacklist refresh token (Authenticated)',
        description="""
        Logout the current user by blacklisting their refresh token.

        **What Happens:**
        - Refresh token is added to the blacklist
        - Token can no longer be used to obtain new access tokens
        - User must login again to get new tokens

        **Prerequisites:**
        - Must be authenticated (Bearer access token in Authorization header)
        - Must provide refresh token in request body

        **Important Notes:**
        - Access token remains valid until its natural expiration (15 minutes)
        - To fully invalidate access immediately, implement token versioning
        - Blacklist is permanent for that specific refresh token
        - After logout, call `/auth/jwt/create/` to login again

        **Security:**
        - Always logout when users click "Sign Out"
        - Helps prevent unauthorized access if refresh token is compromised
        - Token blacklist is stored in database
        """,
        request=LogoutSerializer,
        examples=[
            OpenApiExample(
                'Logout Request',
                value={'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'},
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Logout successful, token blacklisted (no content returned)'),
            400: OpenApiResponse(
                description='Bad Request - Invalid or missing refresh token',
                response=inline_serializer(
                    name='LogoutBadRequestResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message')
                    }
                )
            ),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token in Authorization header'),
        }
    )
    def post(self, request):
        """
        Blacklist the refresh token to log out the user.

        Args:
            request: The HTTP request object containing refresh token

        Returns:
            Response with 204 No Content on success
            Response with 400 Bad Request if token is invalid or missing
        """
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response(
                {'detail': 'Refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except TokenError as e:
            return Response(
                {'detail': 'Invalid token or token already blacklisted.'},
                status=status.HTTP_400_BAD_REQUEST
            )


class CustomUserViewSet(UserViewSet):
    """
    Custom UserViewSet that extends Djoser's UserViewSet.

    Adds JWT token blacklisting functionality to password reset and
    password change operations for enhanced security.
    """

    @extend_schema(
        tags=['User Management'],
        summary='Register new user account (Public)',
        description="""
        Create a new user account with email and password.

        **Registration Flow:**
        1. Submit email, username, and password
        2. Account is created (inactive if activation required)
        3. Activation email is sent (if SEND_ACTIVATION_EMAIL=True)
        4. User must click activation link to activate account
        5. After activation, user can login at `/auth/jwt/create/`

        **Email Activation:**
        - If enabled: Check email for activation link
        - Activation link format: `{FRONTEND_URL}/activate/{uid}/{token}`
        - Click link or call `/auth/users/activation/` with uid/token
        - Account becomes active after successful activation

        **Important Notes:**
        - Email must be unique
        - Username is optional (can login with email)
        - Password must meet validation requirements
        - OAuth users are auto-activated

        **After Registration:**
        - Wait for activation email (if enabled)
        - Activate account via link or API
        - Login at `/auth/jwt/create/` to get tokens
        """,
        examples=[
            OpenApiExample(
                'Registration Request',
                value={
                    'email': 'newuser@example.com',
                    'username': 'newuser',
                    'password': 'SecurePass123!'
                },
                request_only=True,
            ),
            OpenApiExample(
                'Success Response',
                value={
                    'id': 1,
                    'email': 'newuser@example.com',
                    'username': 'newuser'
                },
                response_only=True,
                status_codes=['201'],
            ),
        ],
        responses={
            201: OpenApiResponse(description='User created successfully. Check email for activation if required.'),
            400: OpenApiResponse(
                description='Bad Request - Validation errors',
                response=inline_serializer(
                    name='UserRegistrationErrorResponse',
                    fields={
                        'email': serializers.ListField(help_text='Email validation errors'),
                        'username': serializers.ListField(help_text='Username validation errors'),
                        'password': serializers.ListField(help_text='Password validation errors'),
                    }
                )
            ),
        }
    )
    def create(self, request, *args, **kwargs):
        """
        Create a new user account and associated certificate application.
        
        在創建用戶的同時，如果提供了證書申請相關欄位，則創建 CertificateApplication。
        
        根據請求數據自動選擇合適的 serializer：
        - 如果只包含基本欄位（email, password, username, occupation_category, information_source, clinic_id），
          使用 SimpleUserCreateSerializer
        - 否則使用 UserCreateSerializer（包含完整的證書申請欄位）
        """
        import logging
        from django.db import transaction, IntegrityError
        from django.core.exceptions import ValidationError as DjangoValidationError
        from rest_framework.exceptions import ValidationError as DRFValidationError
        
        logger = logging.getLogger(__name__)
        
        try:
            # 檢查是否應該使用簡化的 serializer
            request_data = request.data
            simple_fields = {
                'email', 
                'password', 
                'username', 
                'occupation_category', 
                'information_source', 
                'clinic_id', 
                'first_name', 
                'last_name', 
                'phone_number',
                'surgery_date',
                'surgeon_name',
            }
            has_only_simple_fields = set(request_data.keys()).issubset(simple_fields)
            
            if has_only_simple_fields:
                from users.serializers import SimpleUserCreateSerializer
                serializer = SimpleUserCreateSerializer(data=request.data)
            else:
                serializer = self.get_serializer(data=request.data)
            
            # 驗證數據
            try:
                serializer.is_valid(raise_exception=True)
            except DRFValidationError as e:
                # 返回 DRF 的驗證錯誤（格式已整理好）
                return Response(
                    {
                        'error': '資料驗證失敗',
                        'details': e.detail
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 提取證書申請相關的欄位
            # 對於 SimpleUserCreateSerializer，這些欄位已經在 validate() 中被 pop 到實例變量中
            # 對於 UserCreateSerializer，這些欄位還在 validated_data 中
            if hasattr(serializer, 'clinic_id'):
                # SimpleUserCreateSerializer：從實例變量獲取
                certificate_fields = {
                    'clinic_id': getattr(serializer, 'clinic_id', None),
                    'surgeon_name': getattr(serializer, 'surgeon_name', None),
                    'surgery_date': getattr(serializer, 'surgery_date', None),
                }
            else:
                # UserCreateSerializer：從 validated_data 中 pop
                certificate_fields = {
                    'clinic_id': serializer.validated_data.pop('clinic_id', None),
                    'surgeon_name': serializer.validated_data.pop('surgeon_name', None),
                    'surgery_date': serializer.validated_data.pop('surgery_date', None),
                }

            # 使用事務確保用戶創建和證書申請創建要麼全部成功，要麼全部回滾
            user = None
            application = None
            token = None
            
            try:
                with transaction.atomic():
                    # 創建用戶（在事務內）
                    user = serializer.save()
                    
                    # 如果提供了證書申請相關欄位，在同一事務中創建 CertificateApplication
                    if certificate_fields.get('clinic_id'):
                        from clinic.models import CertificateApplication, Clinic
                        
                        # 獲取診所
                        try:
                            clinic = Clinic.objects.get(id=certificate_fields['clinic_id'])
                        except Clinic.DoesNotExist:
                            raise ValueError(f'指定的診所不存在 (ID: {certificate_fields.get("clinic_id")})')
                        
                        # 檢查診所是否有 email
                        if not clinic.email:
                            raise ValueError('診所未設置電子郵件地址，無法發送驗證 email')
                        
                        # 獲取諮詢診所（如果提供）
                        consultation_clinic = None
                        if certificate_fields.get('consultation_clinic_id'):
                            try:
                                consultation_clinic = Clinic.objects.get(id=certificate_fields['consultation_clinic_id'])
                            except Clinic.DoesNotExist:
                                raise ValueError(f'指定的諮詢診所不存在 (ID: {certificate_fields.get("consultation_clinic_id")})')
                        
                        # 構建 certificate_data（包含用戶的 email）
                        certificate_data = {
                            'email': user.email,
                        }
                        
                        # 如果有其他證書相關資料，也加入
                        if certificate_fields.get('surgeon_name'):
                            certificate_data['surgeon_name'] = certificate_fields['surgeon_name']
                        if certificate_fields.get('surgery_date'):
                            certificate_data['surgery_date'] = certificate_fields['surgery_date'].strftime('%Y-%m-%d') if hasattr(certificate_fields['surgery_date'], 'strftime') else str(certificate_fields['surgery_date'])
                        
                        # 創建證書申請實例（在事務內）
                        application = CertificateApplication(
                            user=user,
                            clinic=clinic,
                            surgeon_name=certificate_fields.get('surgeon_name'),
                            surgery_date=certificate_fields.get('surgery_date'),
                            certificate_data=certificate_data,
                            create_user=user
                        )
                        
                        # 生成驗證 token（這會設置 verification_token 和 token_expires_at）
                        token = application.generate_verification_token()
                        
                        # 保存申請（在事務內）
                        application.save()
                        
            except IntegrityError as e:
                logger.error(f"Failed to create user due to database integrity error: {e}", exc_info=True)
                error_message = str(e)
                return Response(
                    {
                        'error': '創建用戶失敗',
                        'message': error_message
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            except DjangoValidationError as e:
                logger.error(f"Failed to create user due to validation error: {e}", exc_info=True)
                return Response(
                    {
                        'error': '創建用戶失敗',
                        'message': '資料驗證失敗',
                        'details': e.message_dict if hasattr(e, 'message_dict') else str(e)
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            except ValueError as e:
                # 處理業務邏輯錯誤（診所不存在、email 未設置等）
                logger.error(f"Business logic error: {e}", exc_info=True)
                return Response(
                    {
                        'error': '創建失敗',
                        'message': str(e)
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            except Exception as e:
                logger.error(f"Failed to create user or certificate application: {e}", exc_info=True)
                return Response(
                    {
                        'error': '創建失敗',
                        'message': '系統錯誤，請稍後再試'
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # 確保用戶已創建
            if not user:
                return Response(
                    {
                        'error': '創建失敗',
                        'message': '用戶創建失敗，請稍後再試'
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # 發送郵件（在事務外，避免影響數據保存）
            # 如果提供了證書申請相關欄位，發送證書驗證郵件
            if certificate_fields.get('clinic_id') and application and token:
                from clinic.models import Clinic
                try:
                    clinic = Clinic.objects.get(id=certificate_fields['clinic_id'])
                    if clinic.email:
                        try:
                            self._send_certificate_verification_email(application, token)
                        except Exception as e:
                            logger.error(
                                f"Failed to send verification email for application {application.id}: {e}",
                                exc_info=True
                            )
                            # 即使發送失敗，也繼續（可以稍後重試或手動發送）
                            # 不返回錯誤，因為用戶和證書申請已經創建成功
                except Exception as e:
                    logger.error(f"Failed to send certificate verification email: {e}", exc_info=True)
            
            # 發送註冊成功通知郵件（使用自定義模板）
            try:
                from users.email import RegistrationSuccessEmail
                from django.contrib.sites.models import Site
                
                # 獲取站點名稱
                try:
                    site = Site.objects.get_current()
                    site_name = site.name
                except:
                    site_name = getattr(settings, 'SITE_NAME', '系統')
                
                # 創建並發送註冊成功郵件
                registration_email = RegistrationSuccessEmail(request, {
                    'user': user,
                    'site_name': site_name,
                })
                registration_email.send([user.email])
                
                logger.info(f"Registration success email sent to {user.email} for user {user.id}")
            except Exception as e:
                logger.error(f"Failed to send registration success email for user {user.id}: {e}", exc_info=True)
                # 不阻止響應，因為用戶已經創建成功
            
            headers = self.get_success_headers(serializer.data)
            return Response({
                'message': '用戶創建成功',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED, headers=headers)
            
        except Exception as e:
            # 捕獲所有未預期的錯誤
            logger.error(f"Unexpected error in user creation: {e}", exc_info=True)
            return Response(
                {
                    'error': '系統錯誤',
                    'message': '創建用戶時發生未預期的錯誤，請稍後再試'
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        tags=['User Management'],
        summary='List all users (Authenticated - CurrentUserOrAdmin)',
        description="""
        Retrieve a list of user accounts.

        **Permission:** `CurrentUserOrAdmin`
        - Regular users: Can only see their own user object (returns array with 1 item)
        - Admin users: Can see all users in the system

        **What You Get:**
        - Array of user objects
        - Basic profile information for each user
        - Paginated results (if pagination is enabled)

        **Prerequisites:**
        - Must be authenticated

        **Common Use Cases:**
        - Admin user management interface
        - User directory/search (admin only)
        - Analytics and reporting (admin only)

        **Security:**
        - Regular users will only see themselves in the list
        - Use `/auth/users/me/` for simpler current user access
        """,
        examples=[
            OpenApiExample(
                'Success Response',
                value=[
                    {
                        'id': 1,
                        'email': 'user1@example.com',
                        'username': 'user1'
                    },
                    {
                        'id': 2,
                        'email': 'user2@example.com',
                        'username': 'user2'
                    }
                ],
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(description='List of users retrieved successfully'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to list users'),
        }
    )
    def list(self, request, *args, **kwargs):
        """List all users."""
        return super().list(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Get user by ID (Authenticated - CurrentUserOrAdmin)',
        description="""
        Retrieve a specific user's profile information by their user ID.

        **Permission:** `CurrentUserOrAdmin`
        - Regular users: Can only retrieve their own profile (if ID matches)
        - Admin users: Can retrieve any user's profile

        **What You Get:**
        - User ID
        - Email address
        - Username
        - 2FA status
        - Other profile fields

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Admin user management
        - User lookup by ID for admin purposes
        - Customer support

        **Important Notes:**
        - Different from `/auth/users/me/` which gets current user
        - Regular users cannot view other users' profiles

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` for current user profile instead
        """,
        examples=[
            OpenApiExample(
                'Success Response',
                value={
                    'id': 1,
                    'email': 'user@example.com',
                    'username': 'johndoe',
                    'email_verified': True,
                    'is_2fa_enabled': False
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(description='User profile retrieved successfully'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to view this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def retrieve(self, request, *args, **kwargs):
        """Get user by ID."""
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Update user by ID (Authenticated - CurrentUserOrAdmin - full update)',
        description="""
        Fully update a user's profile information by their user ID (PUT method).

        **What This Does:**
        - Replaces all fields of the user profile
        - Requires all required fields to be provided
        - Uses PUT method (full replacement)

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Admin user management
        - Bulk user updates
        - Profile synchronization

        **Important Notes:**
        - All required fields must be provided
        - Missing fields will be set to default/null
        - Use PATCH for partial updates instead
        - Cannot change password via this endpoint (use set_password)

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` to update your own profile
        - Audit log recommended for user modifications
        """,
        request=inline_serializer(
            name='UserUpdateRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address'),
                'username': serializers.CharField(help_text='Username'),
            }
        ),
        examples=[
            OpenApiExample(
                'Update User Request',
                value={
                    'email': 'updated@example.com',
                    'username': 'updateduser'
                },
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='User updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to update this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def update(self, request, *args, **kwargs):
        """Update user by ID (PUT)."""
        return super().update(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Partially update user by ID (Authenticated - CurrentUserOrAdmin)',
        description="""
        Partially update a user's profile information by their user ID (PATCH method).

        **What This Does:**
        - Updates only the fields provided
        - Other fields remain unchanged
        - Uses PATCH method (partial update)

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Update specific user fields
        - Admin user management
        - Profile field corrections

        **Important Notes:**
        - Only provided fields are updated
        - More flexible than PUT (full update)
        - Cannot change password via this endpoint (use set_password)

        **Difference from PUT:**
        - PATCH: Only updates provided fields
        - PUT: Replaces entire resource (all fields required)

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` to update your own profile
        - Audit log recommended for user modifications
        """,
        request=inline_serializer(
            name='UserPartialUpdateRequest',
            fields={
                'email': serializers.EmailField(required=False, help_text='Email address (optional)'),
                'username': serializers.CharField(required=False, help_text='Username (optional)'),
            }
        ),
        examples=[
            OpenApiExample(
                'Partial Update User Request',
                value={'email': 'newemail@example.com'},
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='User updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to update this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def partial_update(self, request, *args, **kwargs):
        """Partially update user by ID (PATCH)."""
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Delete user by ID (Authenticated - CurrentUserOrAdmin)',
        description="""
        Delete a user account by their user ID.

        **What This Does:**
        - Permanently deletes the user account
        - Cascade deletes related data (tokens, 2FA settings, etc.)
        - Cannot be undone

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Admin user management
        - Account removal requests
        - Cleanup of inactive/spam accounts
        - Ban enforcement

        **Important Notes:**
        - Deletion is permanent and irreversible
        - Related data (tokens, 2FA settings, etc.) will be deleted
        - Consider soft-delete for data retention
        - All JWT tokens for user are automatically invalidated

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` to delete your own account
        - Audit log strongly recommended
        - Consider GDPR/data retention policies

        **After Deletion:**
        - User cannot login
        - All tokens are invalidated
        - Email/username become available for reuse
        - Related data is deleted (cascading)
        """,
        responses={
            204: OpenApiResponse(description='User deleted successfully (no content returned)'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to delete this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def destroy(self, request, *args, **kwargs):
        """Delete user by ID."""
        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        methods=['GET'],
        tags=['User Management'],
        summary='Get current user profile (Authenticated)',
        description="""
        Retrieve the authenticated user's profile information.

        **What You Get:**
        - User ID
        - Email address
        - Username
        - 2FA enabled status
        - Any other profile fields

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Use Cases:**
        - Display user profile in UI
        - Check 2FA status
        - Get user ID for other operations
        """,
        examples=[
            OpenApiExample(
                'Success Response',
                value={
                    'id': 1,
                    'email': 'user@example.com',
                    'username': 'johndoe',
                    'email_verified': True,
                    'is_2fa_enabled': False
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(description='User profile retrieved successfully'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    @extend_schema(
        methods=['PUT'],
        tags=['User Management'],
        summary='Update current user profile (Authenticated - full update)',
        description="""
        Fully update the authenticated user's profile information (PUT method).

        **What This Does:**
        - Replaces all fields of your profile
        - Requires all required fields to be provided
        - Uses PUT method (full replacement)

        **Common Use Cases:**
        - Complete profile update
        - Profile synchronization
        - Change email or username

        **Important Notes:**
        - Must provide all required fields
        - Missing optional fields will be cleared
        - Use PATCH for partial updates instead
        - Cannot change password via this endpoint (use `/auth/users/set_password/`)

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Difference from PATCH:**
        - PUT: Replaces entire profile (all required fields needed)
        - PATCH: Updates only provided fields
        """,
        request=inline_serializer(
            name='UserMeUpdateRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address'),
                'username': serializers.CharField(help_text='Username'),
            }
        ),
        examples=[
            OpenApiExample(
                'Update Profile Request',
                value={
                    'email': 'newemail@example.com',
                    'username': 'newusername'
                },
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='Profile updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    @extend_schema(
        methods=['PATCH'],
        tags=['User Management'],
        summary='Partially update current user profile (Authenticated)',
        description="""
        Partially update the authenticated user's profile information (PATCH method).

        **What This Does:**
        - Updates only the fields provided
        - Other fields remain unchanged
        - Uses PATCH method (partial update)

        **Common Use Cases:**
        - Update email only
        - Update username only
        - Update any single profile field

        **Important Notes:**
        - Only provided fields are updated
        - More flexible than PUT (full update)
        - Cannot change password via this endpoint (use `/auth/users/set_password/`)

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Difference from PUT:**
        - PATCH: Updates only provided fields (recommended)
        - PUT: Replaces entire profile (all required fields needed)
        """,
        request=inline_serializer(
            name='UserMePartialUpdateRequest',
            fields={
                'email': serializers.EmailField(required=False, help_text='Email address (optional)'),
                'username': serializers.CharField(required=False, help_text='Username (optional)'),
            }
        ),
        examples=[
            OpenApiExample(
                'Partial Update Profile Request',
                value={'email': 'newemail@example.com'},
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='Profile updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    @extend_schema(
        methods=['DELETE'],
        tags=['User Management'],
        summary='Delete current user account (Authenticated)',
        description="""
        Delete the authenticated user's own account.

        **What This Does:**
        - Permanently deletes your account
        - Removes all associated data
        - Cannot be undone
        - Immediately invalidates all JWT tokens

        **Common Use Cases:**
        - User-initiated account deletion
        - GDPR "right to be forgotten" requests
        - Account closure

        **Important Notes:**
        - Deletion is permanent and irreversible
        - All related data (2FA settings, tokens, etc.) will be deleted
        - User will be immediately logged out
        - Email/username become available for reuse

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Security Considerations:**
        - Consider adding confirmation step in frontend
        - May want to require password confirmation
        - Consider data export before deletion (GDPR)
        - All JWT tokens are automatically invalidated

        **After Deletion:**
        - Cannot login anymore
        - All tokens are invalidated
        - All data is permanently removed
        - Email can be used to create new account
        """,
        responses={
            204: OpenApiResponse(description='Account deleted successfully (no content returned)'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    def me(self, request, *args, **kwargs):
        """Handle current user profile operations (GET, PUT, PATCH, DELETE)."""
        return super().me(request, *args, **kwargs)
    
    def _send_certificate_verification_email(self, application, token):
        """
        發送驗證 email 到診所（使用與 SubmitCertificateApplicationView 相同的邏輯）
        
        Args:
            application: CertificateApplication 實例
            token: 驗證 token
            
        Raises:
            Exception: 如果發送失敗
        """
        from django.core.mail import send_mail
        from django.utils.html import strip_tags
        from django.conf import settings
        import logging
        
        logger = logging.getLogger(__name__)
        
        if not application.clinic.email:
            raise ValueError(f"Clinic {application.clinic.id} does not have an email address")
        
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        
        # 構建驗證連結
        verification_url = f"{frontend_url}/certificate/verify?token={token}"
        
        # 構建 email 內容
        subject = '證書申請驗證 - 請確認證書發放'
        
        # 從用戶獲取申請人資訊
        applicant_name = application.get_applicant_name()
        applicant_email = application.get_applicant_email()
        applicant_phone = application.get_applicant_phone()
        surgeon_name = application.surgeon_name or application.certificate_data.get('surgeon_name', '未提供')
        surgery_date = application.surgery_date.strftime('%Y-%m-%d') if application.surgery_date else application.certificate_data.get('surgery_date', '未提供')
        
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
                <li><strong>手術醫師：</strong>{surgeon_name}</li>
                <li><strong>手術日期：</strong>{surgery_date or '未提供'}</li>
                <li><strong>申請時間：</strong>{application.create_time.strftime('%Y-%m-%d %H:%M:%S')}</li>
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
            f"Verification email sent successfully to {application.clinic.email} "
            f"for application {application.id} (user: {application.user.id}, clinic: {application.clinic.id})"
        )

    @extend_schema(
        tags=['User Management'],
        summary='Activate user account (Public)',
        description="""
        Activate a user account using the UID and token from activation email.

        **Activation Flow:**
        1. User registers at `/auth/users/`
        2. System sends activation email with uid and token
        3. User clicks link or frontend calls this endpoint
        4. Account becomes active
        5. User can now login

        **Email Link Format:**
        - Link in email: `{FRONTEND_URL}/activate/{uid}/{token}`
        - Frontend should extract uid/token and call this endpoint

        **Important Notes:**
        - Token is single-use only
        - Token expires after 24 hours (configurable)
        - Already active accounts will return error
        - After activation, login at `/auth/jwt/create/`

        **Common Errors:**
        - Invalid uid/token: Token expired or already used
        - Already activated: Account is already active
        """,
        request=inline_serializer(
            name='ActivationRequest',
            fields={
                'uid': serializers.CharField(help_text='User ID from activation email'),
                'token': serializers.CharField(help_text='Activation token from email'),
            }
        ),
        examples=[
            OpenApiExample(
                'Activation Request',
                value={
                    'uid': 'MQ',
                    'token': 'abc123-def456-ghi789'
                },
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Account activated successfully (no content returned)'),
            400: OpenApiResponse(
                description='Bad Request - Invalid uid/token or account already active',
                response=inline_serializer(
                    name='ActivationErrorResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message'),
                    }
                )
            ),
        }
    )
    def activation(self, request, *args, **kwargs):
        """Activate user account with uid and token."""
        return super().activation(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Resend activation email (Public)',
        description="""
        Resend the account activation email to the user.

        **Use Cases:**
        - User didn't receive activation email
        - Activation link expired
        - Email was accidentally deleted

        **What Happens:**
        1. Validates the email exists in system
        2. Checks if account is already active
        3. Generates new uid and token
        4. Sends new activation email

        **Important Notes:**
        - Only works for inactive accounts
        - Previous activation links become invalid
        - New token expires in 24 hours

        **After Receiving Email:**
        - Click activation link or call `/auth/users/activation/`
        """,
        request=inline_serializer(
            name='ResendActivationRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address of account to activate'),
            }
        ),
        examples=[
            OpenApiExample(
                'Resend Activation Request',
                value={'email': 'user@example.com'},
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Activation email sent successfully (no content returned)'),
            400: OpenApiResponse(
                description='Bad Request - Account already active or email not found',
                response=inline_serializer(
                    name='ResendActivationErrorResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message'),
                    }
                )
            ),
        }
    )
    def resend_activation(self, request, *args, **kwargs):
        """Resend activation email to user."""
        return super().resend_activation(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Request password reset (Public)',
        description="""
        Request a password reset email for forgotten password.

        **Password Reset Flow:**
        1. Call this endpoint with email
        2. System sends password reset email
        3. User clicks link in email
        4. Frontend calls `/auth/users/reset_password_confirm/` with uid/token/new password
        5. Password is changed and all tokens are blacklisted

        **Email Link Format:**
        - Link in email: `{FRONTEND_URL}/password/reset/confirm/{uid}/{token}`
        - Frontend should show password reset form
        - Frontend extracts uid/token and submits with new password

        **Important Notes:**
        - Always returns 204 even if email doesn't exist (security)
        - Token expires after 24 hours (configurable)
        - Token is single-use only
        - After reset, all JWT tokens are blacklisted

        **Security:**
        - Doesn't reveal if email exists in system
        - Tokens are cryptographically secure
        """,
        request=inline_serializer(
            name='ResetPasswordRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address of account to reset'),
            }
        ),
        examples=[
            OpenApiExample(
                'Password Reset Request',
                value={'email': 'user@example.com'},
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Password reset email sent (or silently ignored if email not found)'),
        }
    )
    def reset_password(self, request, *args, **kwargs):
        """Send password reset email."""
        return super().reset_password(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Confirm password reset with new password (Public)',
        description="""
        Complete the password reset process with uid, token, and new password.

        **Reset Confirmation Flow:**
        1. User received password reset email
        2. Clicked link: `{FRONTEND_URL}/password/reset/confirm/{uid}/{token}`
        3. Frontend shows password reset form
        4. User enters new password
        5. Frontend calls this endpoint with uid, token, and new password
        6. Password is changed
        7. **ALL JWT tokens are automatically blacklisted**
        8. User must login again with new password

        **Important Notes:**
        - Token is single-use only
        - Token expires after 24 hours
        - New password must meet validation requirements
        - All existing sessions are invalidated (tokens blacklisted)
        - User must login at `/auth/jwt/create/` after reset

        **Security:**
        - Forces re-authentication after password reset
        - Invalidates all existing sessions
        - Prevents unauthorized access if password was compromised
        - This happens ALWAYS, regardless of settings

        **After Success:**
        1. All JWT tokens are blacklisted
        2. User receives password changed confirmation email
        3. User must login with new password
        """,
        request=inline_serializer(
            name='ResetPasswordConfirmRequest',
            fields={
                'uid': serializers.CharField(help_text='User ID from reset email'),
                'token': serializers.CharField(help_text='Reset token from email'),
                'new_password': serializers.CharField(help_text='New password to set'),
            }
        ),
        examples=[
            OpenApiExample(
                'Password Reset Confirm Request',
                value={
                    'uid': 'MQ',
                    'token': 'abc123-def456-ghi789',
                    'new_password': 'NewSecurePass123!'
                },
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Password reset successful. All JWT tokens blacklisted. Login required.'),
            400: OpenApiResponse(
                description='Bad Request - Invalid uid/token or password validation failed',
                response=inline_serializer(
                    name='ResetPasswordConfirmErrorResponse',
                    fields={
                        'uid': serializers.ListField(help_text='UID validation errors'),
                        'token': serializers.ListField(help_text='Token validation errors'),
                        'new_password': serializers.ListField(help_text='Password validation errors'),
                    }
                )
            ),
        }
    )
    def reset_password_confirm(self, request, *args, **kwargs):
        """
        Override password reset confirm to blacklist all user tokens.

        After a successful password reset, all existing JWT refresh tokens
        are blacklisted to force re-authentication for security purposes.
        This ALWAYS happens on password reset, regardless of settings.
        """
        # Call parent method to handle password reset
        response = super().reset_password_confirm(request, *args, **kwargs)

        # If password reset was successful, blacklist all tokens
        if response.status_code == status.HTTP_204_NO_CONTENT:
            # Extract user from serializer
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = serializer.user
                blacklist_user_tokens(user)

        return response

    @extend_schema(
        tags=['User Management'],
        summary='Change password (Authenticated)',
        description="""
        Change the password for the currently authenticated user.

        **Password Change Flow:**
        1. User must be logged in (authenticated)
        2. Provide current password and new password
        3. Password is changed
        4. **Optional:** JWT tokens may be blacklisted (if enabled in settings)
        5. User receives password changed confirmation email

        **Token Blacklisting:**
        - Controlled by `BLACKLIST_TOKENS_ON_PASSWORD_CHANGE` setting
        - If `True`: All JWT tokens are blacklisted, user must login again
        - If `False`: Current session remains active (default)

        **Important Notes:**
        - Must provide correct current password
        - New password must meet validation requirements
        - New password cannot be same as current password
        - After change, check if you need to re-login

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Difference from Password Reset:**
        - This requires current password (user is logged in)
        - Password reset is for forgotten passwords (uses email)
        - Password reset ALWAYS blacklists tokens
        - This only blacklists if setting is enabled

        **Security:**
        - Requires current password to prevent unauthorized changes
        - Password validation enforced
        - Email confirmation sent
        """,
        request=inline_serializer(
            name='SetPasswordRequest',
            fields={
                'current_password': serializers.CharField(help_text='Current password for verification'),
                'new_password': serializers.CharField(help_text='New password to set'),
            }
        ),
        examples=[
            OpenApiExample(
                'Change Password Request',
                value={
                    'current_password': 'OldPass123!',
                    'new_password': 'NewSecurePass123!'
                },
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Password changed successfully. Check BLACKLIST_TOKENS_ON_PASSWORD_CHANGE setting to see if re-login required.'),
            400: OpenApiResponse(
                description='Bad Request - Validation errors',
                response=inline_serializer(
                    name='SetPasswordErrorResponse',
                    fields={
                        'current_password': serializers.ListField(help_text='Current password errors'),
                        'new_password': serializers.ListField(help_text='New password validation errors'),
                    }
                )
            ),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    def set_password(self, request, *args, **kwargs):
        """
        Override password change to conditionally blacklist tokens.

        After a successful password change, JWT refresh tokens are blacklisted
        ONLY if BLACKLIST_TOKENS_ON_PASSWORD_CHANGE setting is True.
        """
        # Call parent method to handle password change
        response = super().set_password(request, *args, **kwargs)

        # If password change was successful and setting is enabled
        if (response.status_code == status.HTTP_204_NO_CONTENT and
            getattr(settings, 'BLACKLIST_TOKENS_ON_PASSWORD_CHANGE', False)):
            # Blacklist all tokens for this user
            blacklist_user_tokens(request.user)

        return response


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(role__in=[
        UserRole.SUPER_ADMIN, 
        UserRole.ADMIN, 
        UserRole.CLINIC_ADMIN, 
        UserRole.CLINIC_STAFF
    ]).order_by("-date_joined")
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminRolePermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
    ]
    filterset_class = UserFilterSet
    ordering_fields = [
        "first_name",
        "last_name",
        "is_active",
        "username",
        "last_login",
        "email",
        "phone_number",
        "role",
        "created_at",
        "updated_at",
    ]
    ordering = ["username"]
    pagination_class = StandardResultsSetPagination

    def create(self, request, *args, **kwargs):
        """
        創建用戶資料，並處理診所權限
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # 提取 clinic_ids（如果提供）
        clinic_ids = serializer.validated_data.pop('clinic_ids', None)
        
        # 創建用戶
        user = serializer.save()
        
        # 設置診所權限（如果提供了 clinic_ids）
        if clinic_ids is not None:
            self._update_clinic_permissions(user, clinic_ids)
        
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )

    def _update_clinic_permissions(self, user, clinic_ids):
        """
        更新用戶的診所權限
        
        Args:
            user: User 實例
            clinic_ids: 診所 ID 列表
        """
        if ClinicUserPermission is None or Clinic is None:
            return
        
        # 獲取當前用戶的診所權限
        current_permissions = ClinicUserPermission.objects.filter(user=user)
        current_clinic_ids = set(current_permissions.values_list('clinic_id', flat=True))
        target_clinic_ids = set(clinic_ids) if clinic_ids else set()
        
        # 找出需要添加的診所
        to_add = target_clinic_ids - current_clinic_ids
        # 找出需要刪除的診所
        to_remove = current_clinic_ids - target_clinic_ids
        
        # 添加新的權限
        for clinic_id in to_add:
            clinic = Clinic.objects.get(id=clinic_id)
            # 檢查是否已存在（避免重複）
            if not ClinicUserPermission.objects.filter(user=user, clinic=clinic).exists():
                ClinicUserPermission.objects.create(
                    user=user,
                    clinic=clinic,
                    create_user=self.request.user if self.request.user.is_authenticated else None
                )
        
        # 刪除不需要的權限
        if to_remove:
            ClinicUserPermission.objects.filter(
                user=user,
                clinic_id__in=to_remove
            ).delete()

    def update(self, request, *args, **kwargs):
        """
        更新用戶資料，並處理診所權限
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        
        # 提取 clinic_ids（如果提供）
        clinic_ids = serializer.validated_data.pop('clinic_ids', None)
        
        # 更新用戶資料
        self.perform_update(serializer)
        
        # 更新診所權限（如果提供了 clinic_ids）
        if clinic_ids is not None:
            self._update_clinic_permissions(instance, clinic_ids)
        
        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}
        
        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        """
        部分更新用戶資料，並處理診所權限
        """
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        無法刪除用戶資料。
        """
        return Response(
            {"detail": "無法刪除用戶資料。"},
            status=status.HTTP_403_FORBIDDEN
        )


class ClientUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(role=UserRole.CLIENT).order_by("-date_joined")
    serializer_class = ClientUserSerializer
    permission_classes = [IsAuthenticated, IsAdminRolePermission]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
    ]
    fields = (
        "first_name",
        "last_name",
        "is_active",
        "username",
        "phone_number",
        "is_2fa_enabled",
        "preferred_2fa_method",
        "last_login",
        "email",
        "role",
        "created_at",
        "updated_at",
    )
    filterset_fields = fields
    ordering_fields = fields
    ordering = ["username"]
    pagination_class = StandardResultsSetPagination

    def destroy(self, request, *args, **kwargs):
        """
        無法刪除用戶資料。
        """
        return Response(
            {"detail": "無法刪除用戶資料。"},
            status=status.HTTP_403_FORBIDDEN
        )


class ClientUserOuterViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(role=UserRole.CLIENT).order_by("-date_joined")
    serializer_class = ClientUserSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
    ]
    fields = (
        "first_name",
        "last_name",
        "is_active",
        "username",
        "phone_number",
        "is_2fa_enabled",
        "preferred_2fa_method",
        "last_login",
        "email",
        "role",
        "created_at",
        "updated_at",
    )
    filterset_fields = fields
    ordering_fields = fields
    ordering = ["username"]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """
        只返回當前用戶自己的資料（且 role 為 CLIENT）。
        """
        return User.objects.filter(
            id=self.request.user.id
        ).order_by("-date_joined")

    def update(self, request, *args, **kwargs):
        """
        確保只能更新自己的資料。
        """
        instance = self.get_object()
        if instance.id != request.user.id:
            return Response(
                {"detail": "您只能更新自己的資料。"},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        """
        確保只能部分更新自己的資料。
        """
        instance = self.get_object()
        if instance.id != request.user.id:
            return Response(
                {"detail": "您只能更新自己的資料。"},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        無法刪除用戶資料。
        """
        return Response(
            {"detail": "無法刪除用戶資料。"},
            status=status.HTTP_403_FORBIDDEN
        )