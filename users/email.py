"""
Custom Djoser email classes.

These classes override Djoser's default email templates to use custom templates
and properly use FRONTEND_URL instead of Django Site domain.
"""

from django.conf import settings
from djoser import email


def parse_frontend_url():
    """
    Parse FRONTEND_URL to extract protocol and domain separately.

    This prevents double protocol issues when templates use {{ protocol }}://{{ domain }}
    format. The FRONTEND_URL can be specified with or without protocol.

    Returns:
        tuple: (protocol, domain) where protocol is 'http' or 'https',
               and domain is the URL without protocol

    Examples:
        - 'http://localhost:3000' -> ('http', 'localhost:3000')
        - 'https://app.example.com' -> ('https', 'app.example.com')
        - 'localhost:3000' -> ('http', 'localhost:3000')
        - 'example.com' -> ('https', 'example.com')
    """
    frontend_url = settings.CLIENT_FRONTEND_URL

    if frontend_url.startswith("http://"):
        return "http", frontend_url.replace("http://", "")
    elif frontend_url.startswith("https://"):
        return "https", frontend_url.replace("https://", "")
    else:
        # No protocol specified, assume http for localhost, https otherwise
        protocol = (
            "http"
            if "localhost" in frontend_url or "127.0.0.1" in frontend_url
            else "https"
        )
        return protocol, frontend_url


class ActivationEmail(email.ActivationEmail):
    """
    Custom activation email that uses FRONTEND_URL.

    Uses template: users/templates/email/activation.html
    """

    template_name = "email/custom_activation.html"

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Use FRONTEND_URL from settings instead of Django Site
        uid = context.get("uid")
        token = context.get("token")

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context["protocol"] = protocol
        context["domain"] = domain

        # Reconstruct URL using FRONTEND_URL
        activation_url = settings.DJOSER.get(
            "ACTIVATION_URL", "auth/users/activation/{uid}/{token}"
        )
        context["url"] = activation_url.format(uid=uid, token=token)

        return context


class ConfirmationEmail(email.ConfirmationEmail):
    """
    Custom confirmation email.

    Uses template: users/templates/email/confirmation.html
    """

    template_name = "email/custom_confirmation.html"


class PasswordResetEmail(email.PasswordResetEmail):
    """
    Custom password reset email that uses FRONTEND_URL.

    Uses template: users/templates/email/password_reset.html
    """

    template_name = "email/custom_password_reset.html"

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Use FRONTEND_URL from settings
        uid = context.get("uid")
        token = context.get("token")

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context["protocol"] = protocol
        context["domain"] = domain

        # Reconstruct URL using FRONTEND_URL
        reset_url = settings.DJOSER.get(
            "PASSWORD_RESET_CONFIRM_URL", "reset-password/{uid}/{token}"
        )
        context["url"] = reset_url.format(uid=uid, token=token)

        return context


class PasswordChangedConfirmationEmail(email.PasswordChangedConfirmationEmail):
    """
    Custom password changed confirmation email.

    Uses template: users/templates/email/password_changed_confirmation.html
    """

    template_name = "email/custom_password_changed_confirmation.html"

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context["protocol"] = protocol
        context["domain"] = domain

        return context


class RegistrationSuccessEmail(email.BaseEmailMessage):
    """
    自定義的註冊成功通知郵件。

    使用模板: users/templates/email/registration_success.html
    """

    template_name = "email/registration_success.html"
    subject = "歡迎註冊 - 帳號建立成功"

    def get_context_data(self):
        """獲取郵件上下文數據"""
        context = super().get_context_data()

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context["protocol"] = protocol
        context["domain"] = domain

        # 如果有激活 URL，添加到上下文
        user = context.get("user")
        if user and not user.is_active:
            try:
                from djoser.utils import encode_uid

                # 使用 Djoser 的 token generator
                uid = encode_uid(user.pk)
                # 嘗試獲取 token generator
                try:
                    from djoser import tokens

                    token = tokens.default_token_generator.make_token(user)
                except ImportError:
                    # 如果無法導入，使用備用方法
                    from django.contrib.auth.tokens import default_token_generator

                    token = default_token_generator.make_token(user)

                activation_url = settings.DJOSER.get(
                    "ACTIVATION_URL", "auth/users/activation/{uid}/{token}"
                )
                context["activation_url"] = (
                    f"{protocol}://{domain}/{activation_url.format(uid=uid, token=token)}"
                )
            except Exception:
                # 如果生成失敗，不包含激活 URL
                context["activation_url"] = None
        else:
            context["activation_url"] = None

        return context

    def send(self, to, *args, **kwargs):
        """
        重寫 send 方法以使用密件副本（BCC）保護個資。

        Args:
            to: 收件人列表（將被移到 BCC）
            *args, **kwargs: 其他參數
        """
        # 將收件人移到 BCC，To 欄位設為空
        # Djoser 的 BaseEmailMessage 使用 EmailMultiAlternatives
        # 我們需要重寫 send 方法來設置 BCC

        # 調用父類方法創建郵件對象
        # BaseEmailMessage 的 send 方法會調用 _get_message() 來創建郵件對象
        # 我們需要先獲取郵件對象，然後修改其 to 和 bcc 屬性
        try:
            # 獲取郵件對象（EmailMultiAlternatives 實例）
            msg = self._get_message()

            # 檢查郵件內容是否為空
            # 如果 subject 或 body 為空，使用備用方法
            if not msg.subject or (
                not msg.body and not (hasattr(msg, "alternatives") and msg.alternatives)
            ):
                raise ValueError("Email content is empty, using fallback method")

            # 將收件人列表轉換為列表格式
            bcc_list = to if isinstance(to, list) else [to]

            # 清空 To 欄位，將收件人移到 BCC
            msg.to = []
            msg.bcc = bcc_list

            # 發送郵件
            return msg.send()
        except (AttributeError, Exception):
            # 如果 _get_message 不存在或失敗，使用備用方法
            # 直接在代碼中定義模板內容
            from django.template import Context, Engine
            from django.core.mail import EmailMultiAlternatives

            # 獲取郵件內容
            context = self.get_context_data()

            # 定義 subject 模板
            subject_template_str = "歡迎註冊 - 帳號建立成功"

            # 定義 HTML body 模板
            html_body_template_str = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>帳號建立成功</title>
</head>
<body style="font-family: Arial, 'Microsoft JhengHei', sans-serif; line-height: 1.6;
    color: #333; margin: 0; padding: 0; background-color: #f4f4f4;">
    <div style="max-width: 600px; margin: 20px auto; background-color: #ffffff;
        border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <!-- Header -->
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px 20px; text-align: center;">
            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: bold;">歡迎加入！</h1>
            <p style="color: #ffffff; margin: 10px 0 0 0; font-size: 16px;">您的帳號已成功建立</p>
        </div>

        <!-- Content -->
        <div style="padding: 30px 20px;">
            <p style="font-size: 16px; margin: 0 0 20px 0;">親愛的 {{ user.get_full_name|default:user.username }}，</p>

            <p style="font-size: 16px; margin: 0 0 20px 0;">
                恭喜！您的帳號已成功建立。以下是您的帳號資訊：
            </p>

            <div style="background-color: #f9f9f9; padding: 20px; border-radius: 5px;
                margin: 20px 0; border-left: 4px solid #667eea;">
                <p style="margin: 10px 0; font-size: 14px;">
                    <strong>電子郵件：</strong>{{ user.email }}
                </p>
                {% if user.username %}
                <p style="margin: 10px 0; font-size: 14px;">
                    <strong>使用者名稱：</strong>{{ user.username }}
                </p>
                {% endif %}
                <p style="margin: 10px 0; font-size: 14px;">
                    <strong>註冊時間：</strong>{{ user.date_joined|date:"Y年m月d日 H:i" }}
                </p>
            </div>

            {% if not user.is_active and activation_url %}
            <div style="background-color: #fff3cd; border: 1px solid #ffc107;
                border-radius: 5px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0 0 10px 0; font-size: 14px; color: #856404;">
                    <strong>⚠️ 重要：</strong>您的帳號尚未啟用，請點擊下方按鈕啟用您的帳號。
                </p>
                <div style="text-align: center; margin: 20px 0;">
                    <a href="{{ activation_url }}"
                        style="background-color: #667eea; color: #ffffff;
                        padding: 12px 30px; text-decoration: none; border-radius: 5px;
                        display: inline-block; font-weight: bold; font-size: 16px;">
                        啟用帳號
                    </a>
                </div>
                <p style="margin: 10px 0 0 0; font-size: 12px; color: #856404;">
                    或複製以下連結到瀏覽器：<br>
                    <a href="{{ activation_url }}"
                        style="color: #667eea; word-break: break-all;">
                        {{ activation_url }}
                    </a>
                </p>
            </div>
            {% else %}
            <div style="background-color: #d4edda; border: 1px solid #c3e6cb;
                border-radius: 5px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; font-size: 14px; color: #155724;">
                    <strong>✓ 您的帳號已啟用</strong>，現在就可以開始使用！
                </p>
            </div>
            {% endif %}

            <div style="margin: 30px 0;">
                <p style="font-size: 16px; margin: 0 0 15px 0;"><strong>下一步：</strong></p>
                <ul style="font-size: 14px; margin: 0; padding-left: 20px;">
                    {% if not user.is_active %}
                    <li style="margin: 8px 0;">點擊上方按鈕啟用您的帳號</li>
                    {% endif %}
                    <li style="margin: 8px 0;">前往登入頁面開始使用服務</li>
                    <li style="margin: 8px 0;">如有任何問題，請聯繫客服</li>
                </ul>
            </div>

            <div style="text-align: center; margin: 30px 0;">
                <a href="{{ protocol }}://{{ domain }}/login"
                    style="background-color: #667eea; color: #ffffff;
                    padding: 12px 30px; text-decoration: none; border-radius: 5px;
                    display: inline-block; font-weight: bold;">
                    前往登入
                </a>
            </div>
        </div>

        <!-- Footer -->
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center; border-top: 1px solid #e9ecef;">
            <p style="margin: 0; font-size: 12px; color: #6c757d;">
                此為系統自動發送，請勿回覆此郵件。<br>
                如有任何疑問，請聯繫客服或訪問我們的網站。
            </p>
        </div>
    </div>
</body>
</html>"""

            # 定義 text body 模板
            text_body_template_str = """親愛的 {{ user.get_full_name|default:user.username }}，

恭喜！您的帳號已成功建立。

帳號資訊：
- 電子郵件：{{ user.email }}
{% if user.username %}- 使用者名稱：{{ user.username }}{% endif %}
- 註冊時間：{{ user.date_joined|date:"Y年m月d日 H:i" }}

{% if not user.is_active and activation_url %}
重要：您的帳號尚未啟用，請點擊以下連結啟用您的帳號：

{{ activation_url }}

此驗證連結即將過期，請盡快驗證您的電子郵件。
{% else %}
您的帳號已啟用，現在就可以開始使用！
{% endif %}

下一步：
{% if not user.is_active %}- 點擊上方連結啟用您的帳號
{% endif %}- 前往登入頁面開始使用服務
- 如有任何問題，請聯繫客服

登入連結：{{ protocol }}://{{ domain }}/login

謝謝，
{{ site_name }} 團隊

---
此為系統自動發送，請勿回覆此郵件。"""

            # 使用 Django 模板系統渲染內容
            try:
                engine = Engine.get_default()

                # 渲染 subject
                subject_template = engine.from_string(subject_template_str)
                subject = subject_template.render(Context(context)).strip()

                # 渲染 HTML body
                html_template = engine.from_string(html_body_template_str)
                html_body = html_template.render(Context(context))

                # 渲染 text body
                text_template = engine.from_string(text_body_template_str)
                text_body = text_template.render(Context(context))

            except Exception:
                # 如果渲染失敗，使用預設值
                subject = self.subject
                text_body = f"親愛的 {context.get('user', {}).get('username', '用戶')}，\n\n恭喜！您的帳號已成功建立。"
                html_body = ""

            # 使用 EmailMultiAlternatives 發送，並設置 BCC
            bcc_list = to if isinstance(to, list) else [to]
            email_msg = EmailMultiAlternatives(
                subject=subject,
                body=text_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                bcc=bcc_list,
            )
            if html_body:
                email_msg.attach_alternative(html_body, "text/html")
            return email_msg.send(fail_silently=False)
