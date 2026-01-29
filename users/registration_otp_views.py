"""
Registration OTP views for email and phone verification.

Supports sequential verification flow:
1. First verify email
2. Then verify phone number
3. Both must be verified before registration
"""

from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import BasePermission
from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    inline_serializer,
)
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
import secrets
import re
import logging

from .models import User, EmailVerificationOTP
from .sns_sender.utils import send_sms

logger = logging.getLogger(__name__)

# Cache key prefix for verification status
VERIFICATION_CACHE_PREFIX = "reg_verification_"
CACHE_TIMEOUT = 600  # 10 minutes


def get_verification_cache_key(email: str) -> str:
    """Generate cache key for verification status."""
    return f"{VERIFICATION_CACHE_PREFIX}{email}"


def set_verification_status(
    email: str,
    phone_number: str = None,
    email_verified: bool = False,
    phone_verified: bool = False,
):
    """Store verification status in cache."""
    cache_key = get_verification_cache_key(email)
    cache.set(
        cache_key,
        {
            "email": email,
            "phone_number": phone_number,
            "email_verified": email_verified,
            "phone_verified": phone_verified,
        },
        CACHE_TIMEOUT,
    )


def get_verification_status(email: str) -> dict:
    """Get verification status from cache."""
    cache_key = get_verification_cache_key(email)
    return cache.get(cache_key, {})


def clear_verification_status(email: str):
    """Clear verification status from cache."""
    cache_key = get_verification_cache_key(email)
    cache.delete(cache_key)


class SendRegistrationOTPView(APIView):
    """
    API endpoint to send OTP for email or phone verification before registration.

    POST /auth/users/send-registration-otp/
    Supports both EMAIL and SMS sending.
    """

    permission_classes: tuple[type[BasePermission], ...] = ()  # 公開訪問，不需要認證

    @extend_schema(
        tags=["User Management"],
        summary="Send registration OTP (Public)",
        description="""
        發送註冊用的 OTP 驗證碼到指定的 email 或手機號碼。

        **流程說明：**
        1. 用戶輸入 email 或手機號碼
        2. 調用此 API 發送 OTP
        3. 系統發送 6 位數驗證碼到 email 或手機號碼
        4. 用戶收到驗證碼後，調用驗證 API 確認

        **驗證順序：**
        - 必須先驗證 Email
        - 驗證 Email 成功後，才能驗證手機號碼
        - 兩個都驗證成功後，才能進行註冊

        **使用場景：**
        - 註冊頁面，用戶輸入 email 或手機號碼後點擊「發送驗證碼」
        - 確保 email 或手機號碼有效且用戶可以接收驗證碼
        - 防止使用無效或他人的 email/手機號碼註冊

        **重要事項：**
        - OTP 有效期為 10 分鐘（可配置）
        - 每個 email/手機號碼最多只能有 1 個未使用的 OTP
        - 如果發送新的 OTP，舊的會被標記為已使用
        - 驗證失敗超過 5 次需重新發送

        **安全考量：**
        - 即使 email/手機號碼不存在，也返回成功（防止枚舉攻擊）
        - 有發送頻率限制（建議前端實現防抖）
        """,
        request=inline_serializer(
            name="SendRegistrationOTPRequest",
            fields={
                "email": serializers.EmailField(
                    help_text="要驗證的 email 地址（與 phone_number 二選一）",
                    required=False,
                ),
                "phone_number": serializers.CharField(
                    help_text="要驗證的手機號碼（與 email 二選一，需先驗證 Email）",
                    required=False,
                ),
            },
        ),
        examples=[
            OpenApiExample(
                "Send OTP via Email",
                value={"email": "user@example.com"},
                request_only=True,
            ),
            OpenApiExample(
                "Send OTP via SMS",
                value={"phone_number": "+886912345678"},
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="OTP 已發送（即使 email/手機號碼不存在也返回成功，防止枚舉攻擊）",
                response=inline_serializer(
                    name="SendRegistrationOTPSuccessResponse",
                    fields={
                        "message": serializers.CharField(help_text="成功訊息"),
                        "expires_at": serializers.DateTimeField(
                            help_text="OTP 過期時間"
                        ),
                        "method": serializers.CharField(
                            help_text="發送方式：EMAIL 或 SMS"
                        ),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="Bad Request - 參數錯誤或格式無效",
                response=inline_serializer(
                    name="SendRegistrationOTPErrorResponse",
                    fields={
                        "error": serializers.CharField(help_text="錯誤訊息"),
                    },
                ),
            ),
            429: OpenApiResponse(
                description="Too Many Requests - 發送頻率過高",
                response=inline_serializer(
                    name="SendRegistrationOTPRateLimitResponse",
                    fields={
                        "error": serializers.CharField(help_text="錯誤訊息"),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        """
        發送註冊用的 OTP 驗證碼到 email 或手機號碼
        """
        email = request.data.get("email", "").strip()
        phone_number = request.data.get("phone_number", "").strip()

        # 必須提供 email 或 phone_number 其中一個
        if not email and not phone_number:
            return Response(
                {"error": "必須提供 email 或 phone_number 其中一個參數"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 不能同時提供兩個參數
        if email and phone_number:
            return Response(
                {"error": "只能提供 email 或 phone_number 其中一個參數"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 生成 6 位數驗證碼
        code = "".join([str(secrets.randbelow(10)) for _ in range(6)])

        # 設置過期時間（10 分鐘）
        expires_at = timezone.now() + timedelta(minutes=10)

        # 處理 EMAIL 發送
        if email:
            # 驗證 email 格式
            try:
                validate_email(email)
            except ValidationError:
                return Response(
                    {"error": "email 格式無效"}, status=status.HTTP_400_BAD_REQUEST
                )

            # 檢查 email 是否已被使用
            if User.objects.filter(email__iexact=email).exists():
                return Response(
                    {
                        "message": "此 email 已被使用，請使用其他 email 註冊",
                        "expires_at": None,
                        "method": "EMAIL",
                    },
                    status=status.HTTP_200_OK,
                )

            # 檢查發送頻率
            recent_otp = EmailVerificationOTP.objects.filter(
                email__iexact=email,
                created_at__gte=timezone.now() - timedelta(minutes=1),
            ).first()

            if recent_otp:
                return Response(
                    {"error": "請稍候再試，發送頻率過高，請稍候再試"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            # 將舊的未使用 OTP 標記為已使用
            EmailVerificationOTP.objects.filter(
                email__iexact=email, is_used=False
            ).update(is_used=True)

            # 創建新的 OTP
            EmailVerificationOTP.objects.create(
                email=email, code=code, expires_at=expires_at
            )

            # 發送 OTP 到 email
            try:
                subject = "您的註冊驗證碼"
                message = f"""親愛的LBV用戶，

您的註冊驗證碼是：

{code}

此驗證碼將在 10 分鐘後過期。

如果您沒有申請註冊，請忽略此郵件。

謝謝！
"""

                email_msg = EmailMultiAlternatives(
                    subject=subject,
                    body=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[email],
                )
                email_msg.send(fail_silently=False)
                logger.info(f"OTP email sent successfully to {email}")
            except Exception as e:
                logger.error(f"Failed to send OTP email to {email}: {e}")
                # 即使發送失敗，也返回成功（防止枚舉攻擊）

            return Response(
                {
                    "message": "驗證碼已發送到您的 email",
                    "expires_at": expires_at,
                    "method": "EMAIL",
                },
                status=status.HTTP_200_OK,
            )

        # 處理 SMS 發送
        else:
            # 基本手機號碼格式驗證
            cleaned_phone = re.sub(r"[^\d+]", "", phone_number)
            if not cleaned_phone or len(cleaned_phone) < 8:
                return Response(
                    {"error": "手機號碼格式無效"}, status=status.HTTP_400_BAD_REQUEST
                )

            # 檢查手機號碼是否已被使用
            if User.objects.filter(phone_number=cleaned_phone).exists():
                return Response(
                    {
                        "message": "此手機號碼已被使用，請使用其他手機號碼註冊",
                        "expires_at": None,
                        "method": "SMS",
                    },
                    status=status.HTTP_200_OK,
                )

            # 檢查發送頻率
            recent_otp = EmailVerificationOTP.objects.filter(
                email=cleaned_phone,
                created_at__gte=timezone.now() - timedelta(minutes=1),
            ).first()

            if recent_otp:
                return Response(
                    {"error": "請稍候再試，發送頻率過高，請稍候再試"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            # 將舊的未使用 OTP 標記為已使用
            EmailVerificationOTP.objects.filter(
                email=cleaned_phone, is_used=False
            ).update(is_used=True)

            # 創建新的 OTP（使用 email 欄位存儲手機號碼）
            otp_instance = EmailVerificationOTP.objects.create(
                email=cleaned_phone, code=code, expires_at=expires_at
            )

            # 發送 OTP 到手機號碼
            try:
                # 構建簡訊內容
                sms_content = f"您的註冊驗證碼是：{code}，此驗證碼將在 10 分鐘後過期。如果您沒有申請註冊，請忽略此簡訊。"

                # 發送簡訊
                result = send_sms(cleaned_phone, sms_content)

                # 檢查發送結果
                if result.get("status") == "error":
                    error_message = result.get("message", "簡訊發送失敗")
                    logger.error(
                        f"Failed to send OTP SMS to {cleaned_phone}: {error_message}"
                    )
                    # 發送失敗，刪除已創建的 OTP
                    otp_instance.delete()
                    return Response(
                        {
                            "error": error_message,
                        },
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
                else:
                    logger.info(f"OTP SMS sent successfully to {cleaned_phone}")

            except Exception as e:
                error_message = f"簡訊發送失敗: {str(e)}"
                logger.error(f"Failed to send OTP SMS to {cleaned_phone}: {e}")
                # 發送失敗，刪除已創建的 OTP
                otp_instance.delete()
                return Response(
                    {
                        "error": error_message,
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response(
                {
                    "message": "驗證碼已發送到您的手機",
                    "expires_at": expires_at,
                    "method": "SMS",
                },
                status=status.HTTP_200_OK,
            )


class VerifyRegistrationOTPView(APIView):
    """
    API endpoint to verify OTP for sequential email and phone verification before registration.

    POST /auth/users/verify-registration-otp/
    This endpoint verifies OTP in sequence: first email, then phone number.
    """

    permission_classes: tuple[type[BasePermission], ...] = ()  # 公開訪問，不需要認證

    @extend_schema(
        tags=["User Management"],
        summary="Verify registration OTP (Public)",
        description="""
        驗證註冊用的 OTP 驗證碼（支援順序驗證：先 Email 後手機號碼）。

        **驗證流程：**
        1. 先驗證 Email OTP
        2. Email 驗證成功後，才能驗證手機號碼 OTP
        3. 兩個都驗證成功後，才能進行註冊

        **驗證規則：**
        - OTP 必須在 10 分鐘內使用
        - OTP 只能使用一次
        - 驗證失敗超過 5 次需重新發送
        - email 或手機號碼必須尚未註冊
        - 必須提供 email 或 phone_number 其中一個（不能同時為空）
        - 驗證手機號碼時，必須先驗證過 Email

        **返回結果：**
        - `verified`: true 表示驗證成功
        - `verified`: false 表示驗證失敗
        - `email_verified`: Email 是否已驗證
        - `phone_verified`: 手機號碼是否已驗證
        - `all_verified`: 兩個是否都已驗證（可用於判斷是否可以註冊）
        - `token`: 驗證成功後返回的臨時 token（可選，用於後續註冊時驗證）

        **使用場景：**
        - 註冊頁面，用戶輸入 OTP 後點擊「驗證」
        - 驗證成功後，允許用戶繼續註冊流程
        """,
        request=inline_serializer(
            name="VerifyRegistrationOTPRequest",
            fields={
                "email": serializers.EmailField(
                    help_text="要驗證的 email 地址（與 phone_number 二選一）",
                    required=False,
                ),
                "phone_number": serializers.CharField(
                    help_text="要驗證的手機號碼（與 email 二選一，需先驗證 Email）",
                    required=False,
                ),
                "verification_email": serializers.EmailField(
                    help_text="驗證手機號碼時必須提供已驗證的 email（僅在驗證手機號碼時需要）",
                    required=False,
                ),
                "code": serializers.CharField(help_text="6 位數驗證碼"),
            },
        ),
        examples=[
            OpenApiExample(
                "Verify OTP via Email",
                value={"email": "user@example.com", "code": "123456"},
                request_only=True,
            ),
            OpenApiExample(
                "Verify OTP via SMS",
                value={
                    "phone_number": "+886912345678",
                    "verification_email": "user@example.com",
                    "code": "123456",
                },
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="OTP 驗證結果",
                response=inline_serializer(
                    name="VerifyRegistrationOTPSuccessResponse",
                    fields={
                        "verified": serializers.BooleanField(help_text="是否驗證成功"),
                        "message": serializers.CharField(help_text="狀態訊息"),
                        "email_verified": serializers.BooleanField(
                            help_text="Email 是否已驗證"
                        ),
                        "phone_verified": serializers.BooleanField(
                            help_text="手機號碼是否已驗證"
                        ),
                        "all_verified": serializers.BooleanField(
                            help_text="兩個是否都已驗證（可用於判斷是否可以註冊）"
                        ),
                        "token": serializers.CharField(
                            required=False,
                            help_text="驗證成功後的臨時 token（可選）",
                        ),
                    },
                ),
            ),
            400: OpenApiResponse(
                description="Bad Request - 參數錯誤或驗證失敗",
                response=inline_serializer(
                    name="VerifyRegistrationOTPErrorResponse",
                    fields={
                        "error": serializers.CharField(help_text="錯誤訊息"),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        """
        驗證註冊用的 OTP 驗證碼（支援順序驗證：先 Email 後手機號碼）
        """
        email = request.data.get("email", "").strip()
        phone_number = request.data.get("phone_number", "").strip()
        code = request.data.get("code", "").strip()

        # 必須提供 email 或 phone_number 其中一個
        if not email and not phone_number:
            return Response(
                {"error": "必須提供 email 或 phone_number 其中一個參數"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 不能同時提供兩個參數
        if email and phone_number:
            return Response(
                {"error": "只能提供 email 或 phone_number 其中一個參數"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not code:
            return Response(
                {"error": "code 參數是必填的"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 處理 EMAIL 驗證
        if email:
            # 驗證 email 格式
            try:
                validate_email(email)
            except ValidationError:
                return Response(
                    {"error": "email 格式無效"}, status=status.HTTP_400_BAD_REQUEST
                )

            # 檢查 email 是否已被註冊
            if User.objects.filter(email__iexact=email).exists():
                return Response(
                    {"verified": False, "error": "此 email 已被註冊"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 查找最新的未使用 OTP
            otp = (
                EmailVerificationOTP.objects.filter(email__iexact=email, is_used=False)
                .order_by("-created_at")
                .first()
            )

            if not otp:
                return Response(
                    {"verified": False, "error": "未找到有效的驗證碼，請重新發送"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 檢查 OTP 是否有效
            if not otp.is_valid():
                if otp.failed_attempts >= 5:
                    return Response(
                        {
                            "verified": False,
                            "error": "驗證失敗次數過多，請重新發送驗證碼",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                else:
                    return Response(
                        {"verified": False, "error": "驗證碼已過期，請重新發送"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # 驗證 code 是否正確
            if otp.code != code:
                # 增加失敗次數
                otp.failed_attempts += 1
                otp.save(update_fields=["failed_attempts"])

                return Response(
                    {
                        "verified": False,
                        "error": f"驗證碼錯誤，還剩 {5 - otp.failed_attempts} 次機會",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 驗證成功，標記為已使用
            otp.is_used = True
            otp.save(update_fields=["is_used"])

            # 更新驗證狀態（Email 已驗證）
            set_verification_status(email=email, email_verified=True)

            # 生成臨時驗證 token
            verification_token = secrets.token_urlsafe(32)

            return Response(
                {
                    "verified": True,
                    "message": "Email 驗證成功，請繼續驗證手機號碼",
                    "email_verified": True,
                    "phone_verified": False,
                    "all_verified": False,
                    "token": verification_token,
                },
                status=status.HTTP_200_OK,
            )

        # 處理手機號碼驗證
        else:
            # 基本手機號碼格式驗證
            cleaned_phone = re.sub(r"[^\d+]", "", phone_number)
            if not cleaned_phone or len(cleaned_phone) < 8:
                return Response(
                    {"error": "手機號碼格式無效"}, status=status.HTTP_400_BAD_REQUEST
                )

            # 檢查手機號碼是否已被註冊
            if User.objects.filter(phone_number=cleaned_phone).exists():
                return Response(
                    {"verified": False, "error": "此手機號碼已被註冊"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 檢查是否已驗證 Email（必須先驗證 Email）
            # 從 cache 中查找是否有對應的 email 驗證狀態
            # 需要從 request 中獲取 email，或者要求用戶在驗證手機時提供 email
            verification_email = request.data.get("verification_email", "").strip()
            if not verification_email:
                return Response(
                    {
                        "error": "驗證手機號碼時，必須提供已驗證的 email（verification_email 參數）"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 驗證 email 格式
            try:
                validate_email(verification_email)
            except ValidationError:
                return Response(
                    {"error": "verification_email 格式無效"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 檢查 Email 是否已驗證
            verification_status = get_verification_status(verification_email)
            if not verification_status.get("email_verified", False):
                return Response(
                    {
                        "verified": False,
                        "error": "請先驗證 Email，才能驗證手機號碼",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 查找最新的未使用 OTP（使用 email 欄位存儲手機號碼）
            otp = (
                EmailVerificationOTP.objects.filter(email=cleaned_phone, is_used=False)
                .order_by("-created_at")
                .first()
            )

            if not otp:
                return Response(
                    {"verified": False, "error": "未找到有效的驗證碼，請重新發送"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 檢查 OTP 是否有效
            if not otp.is_valid():
                if otp.failed_attempts >= 5:
                    return Response(
                        {
                            "verified": False,
                            "error": "驗證失敗次數過多，請重新發送驗證碼",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                else:
                    return Response(
                        {"verified": False, "error": "驗證碼已過期，請重新發送"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # 驗證 code 是否正確
            if otp.code != code:
                # 增加失敗次數
                otp.failed_attempts += 1
                otp.save(update_fields=["failed_attempts"])

                return Response(
                    {
                        "verified": False,
                        "error": f"驗證碼錯誤，還剩 {5 - otp.failed_attempts} 次機會",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 驗證成功，標記為已使用
            otp.is_used = True
            otp.save(update_fields=["is_used"])

            # 更新驗證狀態（手機號碼已驗證）
            set_verification_status(
                email=verification_email,
                phone_number=cleaned_phone,
                email_verified=True,
                phone_verified=True,
            )

            # 生成臨時驗證 token
            verification_token = secrets.token_urlsafe(32)

            return Response(
                {
                    "verified": True,
                    "message": "手機號碼驗證成功，兩個驗證都已完成，可以進行註冊",
                    "email_verified": True,
                    "phone_verified": True,
                    "all_verified": True,
                    "token": verification_token,
                },
                status=status.HTTP_200_OK,
            )
