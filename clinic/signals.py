"""
Signals for Clinic app.
"""

import logging
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.conf import settings
from django.utils.html import strip_tags
from clinic.models import CertificateApplication
from clinic.enums import CertificateApplicationStatus

logger = logging.getLogger(__name__)


@receiver(pre_save, sender=CertificateApplication)
def certificate_application_pre_save(sender, instance, **kwargs):
    """
    在保存前檢查狀態變更，將舊狀態存儲在實例中以便 post_save 使用
    """
    if instance.pk:
        try:
            old_instance = CertificateApplication.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
        except CertificateApplication.DoesNotExist:
            instance._old_status = None
    else:
        instance._old_status = None


@receiver(post_save, sender=CertificateApplication)
def certificate_application_post_save(sender, instance, created, **kwargs):
    """
    當證書申請狀態變更為 cancelled 時，發送取消通知 email 給申請人
    """
    # 如果是新創建的，不需要處理
    if created:
        return

    # 獲取舊狀態（從 pre_save 中設置）
    old_status = getattr(instance, "_old_status", None)
    new_status = instance.status

    # 如果狀態從非 cancelled 變為 cancelled，發送 email
    if (
        old_status != CertificateApplicationStatus.CANCELLED
        and new_status == CertificateApplicationStatus.CANCELLED
    ):
        try:
            _send_cancellation_email(instance)
        except Exception as e:
            logger.error(
                f"Failed to send cancellation email for application {instance.id}: {e}",
                exc_info=True,
            )


def _send_cancellation_email(application):
    """
    發送取消通知 email 給申請人

    Args:
        application: CertificateApplication 實例

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
        logger.warning(
            f"Application {application.id} does not have applicant email address, skipping email"
        )
        return

    # 構建 email 內容
    subject = "證書申請已取消"

    # 獲取申請人資訊
    applicant_name = application.get_applicant_name() or "申請人"
    clinic_name = application.clinic.name if application.clinic else "診所"
    clinic_number = application.clinic.number if application.clinic else "門市"

    # 使用 HTML 模板
    html_message = f"""
    <html>
    <body>
        <h2>證書申請已取消</h2>
        <p>親愛的 {applicant_name}，</p>
        <p>您的證書申請已被取消。</p>
        <ul>
            <li><strong>申請編號：</strong>#{application.id}</li>
            <li><strong>診所名稱：</strong>{clinic_name} - {clinic_number}</li>
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

    # 發送 email（使用密件副本保護個資）
    from django.core.mail import EmailMultiAlternatives

    email_msg = EmailMultiAlternatives(
        subject=subject,
        body=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[applicant_email],
    )
    email_msg.attach_alternative(html_message, "text/html")
    email_msg.send(fail_silently=False)

    logger.info(
        f"Cancellation email sent successfully to {applicant_email} "
        f"for application {application.id}"
    )
