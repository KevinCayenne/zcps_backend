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

    if frontend_url.startswith('http://'):
        return 'http', frontend_url.replace('http://', '')
    elif frontend_url.startswith('https://'):
        return 'https', frontend_url.replace('https://', '')
    else:
        # No protocol specified, assume http for localhost, https otherwise
        protocol = 'http' if 'localhost' in frontend_url or '127.0.0.1' in frontend_url else 'https'
        return protocol, frontend_url


class ActivationEmail(email.ActivationEmail):
    """
    Custom activation email that uses FRONTEND_URL.

    Uses template: users/templates/email/activation.html
    """
    template_name = 'email/custom_activation.html'

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Use FRONTEND_URL from settings instead of Django Site
        uid = context.get('uid')
        token = context.get('token')

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context['protocol'] = protocol
        context['domain'] = domain

        # Reconstruct URL using FRONTEND_URL
        activation_url = settings.DJOSER.get('ACTIVATION_URL', 'auth/users/activation/{uid}/{token}')
        context['url'] = activation_url.format(uid=uid, token=token)

        return context


class ConfirmationEmail(email.ConfirmationEmail):
    """
    Custom confirmation email.

    Uses template: users/templates/email/confirmation.html
    """
    template_name = 'email/custom_confirmation.html'


class PasswordResetEmail(email.PasswordResetEmail):
    """
    Custom password reset email that uses FRONTEND_URL.

    Uses template: users/templates/email/password_reset.html
    """
    template_name = 'email/custom_password_reset.html'

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Use FRONTEND_URL from settings
        uid = context.get('uid')
        token = context.get('token')

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context['protocol'] = protocol
        context['domain'] = domain

        # Reconstruct URL using FRONTEND_URL
        reset_url = settings.DJOSER.get('PASSWORD_RESET_CONFIRM_URL', 'reset-password/{uid}/{token}')
        context['url'] = reset_url.format(uid=uid, token=token)

        return context


class PasswordChangedConfirmationEmail(email.PasswordChangedConfirmationEmail):
    """
    Custom password changed confirmation email.

    Uses template: users/templates/email/password_changed_confirmation.html
    """
    template_name = 'email/custom_password_changed_confirmation.html'

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context['protocol'] = protocol
        context['domain'] = domain

        return context


class RegistrationSuccessEmail(email.BaseEmailMessage):
    """
    自定義的註冊成功通知郵件。
    
    使用模板: users/templates/email/registration_success.html
    """
    template_name = 'email/registration_success.html'
    subject = '歡迎註冊 - 帳號建立成功'
    
    def get_context_data(self):
        """獲取郵件上下文數據"""
        context = super().get_context_data()
        
        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context['protocol'] = protocol
        context['domain'] = domain
        
        # 如果有激活 URL，添加到上下文
        user = context.get('user')
        if user and not user.is_active:
            try:
                from djoser.utils import encode_uid
                from djoser import utils as djoser_utils
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
                
                activation_url = settings.DJOSER.get('ACTIVATION_URL', 'auth/users/activation/{uid}/{token}')
                context['activation_url'] = f"{protocol}://{domain}/{activation_url.format(uid=uid, token=token)}"
            except Exception:
                # 如果生成失敗，不包含激活 URL
                context['activation_url'] = None
        else:
            context['activation_url'] = None
        
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
            
            # 將收件人列表轉換為列表格式
            bcc_list = to if isinstance(to, list) else [to]
            
            # 清空 To 欄位，將收件人移到 BCC
            msg.to = []
            msg.bcc = bcc_list
            
            # 發送郵件
            return msg.send()
        except AttributeError:
            # 如果 _get_message 不存在，使用備用方法
            # 直接調用父類的 send，但這不會使用 BCC
            # 為了安全起見，我們使用 send_mail 直接發送
            from django.core.mail import send_mail
            from django.template.loader import render_to_string
            
            # 獲取郵件內容
            context = self.get_context_data()
            subject = self.subject
            text_body = render_to_string(self.template_name, context).split('{% endblock text_body %}')[0].split('{% block text_body %}')[-1] if '{% block text_body %}' in render_to_string(self.template_name, context) else ''
            html_body = render_to_string(self.template_name, context).split('{% endblock html_body %}')[0].split('{% block html_body %}')[-1] if '{% block html_body %}' in render_to_string(self.template_name, context) else ''
            
            # 使用 send_mail 發送，並設置 BCC
            return send_mail(
                subject=subject,
                message=text_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[],
                bcc=to if isinstance(to, list) else [to],
                html_message=html_body if html_body else None,
                fail_silently=False,
            )