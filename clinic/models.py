from django.db import models
from django.utils.translation import gettext_lazy as _
from config.abstract import BaseModel
from users.models import User
from clinic.enums import CertificateApplicationStatus
import secrets
from django.utils import timezone
from datetime import timedelta

class Clinic(BaseModel):
    """
    Clinic model.
    """
    name = models.CharField(
        max_length=255, 
        verbose_name=_('診所名稱'),
        help_text=_('診所名稱')
    )
    number = models.CharField(
        max_length=255, 
        verbose_name=_('編號'), 
        unique=True,
        help_text=_('診所編號')
    )
    address = models.CharField(
        max_length=255, 
        verbose_name=_('地址'), 
        blank=True, 
        null=True,
        help_text=_('診所地址')
    )
    phone = models.CharField(
        max_length=255, 
        verbose_name=_('電話'), 
        blank=True, 
        null=True, 
        help_text=_('診所電話')
    )
    email = models.EmailField(
        max_length=255, 
        verbose_name=_('電子郵件'), 
        blank=True, 
        null=True,
        help_text=_('診所電子郵件')
    )
    website = models.URLField(
        max_length=255, 
        verbose_name=_('網站'), 
        blank=True, 
        null=True, 
        help_text=_('診所網站')
    )

    class Meta:
        verbose_name = _('診所')
        verbose_name_plural = _('診所')
        ordering = ['-name']

    def __str__(self):
        return self.name


class ClinicUserPermission(BaseModel):
    """
    Clinic user permission model.
    """
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        verbose_name=_('用戶'), 
        related_name='clinic_user_permissions'
    )
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        verbose_name=_('診所'), 
        related_name='clinic_user_permissions'
    )
    
    class Meta:
        verbose_name = _('診所用戶權限')
        verbose_name_plural = _('診所用戶權限')
    
    def __str__(self):
        """返回診所用戶權限的字符串表示"""
        user_name = self.user.username if self.user else 'Unknown'
        clinic_name = self.clinic.name if self.clinic else 'Unknown'
        return f"{user_name} - {clinic_name}"


class Doctor(BaseModel):
    """
    診所醫生 Model
    
    存儲診所醫生的相關資訊。
    """
    # 診所關聯
    clinic = models.ForeignKey(
        Clinic,
        on_delete=models.CASCADE,
        verbose_name=_('診所'),
        related_name='doctors',
        help_text=_('醫生所屬的診所')
    )
    
    # 用戶關聯（可選，如果醫生也是系統用戶）
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        verbose_name=_('用戶'),
        related_name='doctor_profiles',
        blank=True,
        null=True,
        help_text=_('醫生對應的系統用戶（如果醫生也是系統用戶）')
    )
    
    # 基本資訊
    name = models.CharField(
        max_length=255,
        verbose_name=_('醫生姓名'),
        help_text=_('醫生姓名')
    )
    email = models.EmailField(
        max_length=255,
        verbose_name=_('電子郵件'),
        blank=True,
        null=True,
        help_text=_('醫生電子郵件')
    )
    phone = models.CharField(
        max_length=255,
        verbose_name=_('電話'),
        blank=True,
        null=True,
        help_text=_('醫生電話')
    )
    
    # 專業資訊
    license_number = models.CharField(
        max_length=255,
        verbose_name=_('執業執照號碼'),
        blank=True,
        null=True,
        help_text=_('醫生執業執照號碼')
    )
    specialty = models.CharField(
        max_length=255,
        verbose_name=_('專科'),
        blank=True,
        null=True,
        help_text=_('醫生專科（如：內科、外科等）')
    )
    title = models.CharField(
        max_length=255,
        verbose_name=_('職稱'),
        blank=True,
        null=True,
        help_text=_('醫生職稱（如：主任醫師、主治醫師等）')
    )
    
    # 狀態
    is_active = models.BooleanField(
        default=True,
        verbose_name=_('是否啟用'),
        help_text=_('醫生是否仍在該診所執業')
    )
    
    # 備註
    notes = models.TextField(
        verbose_name=_('備註'),
        blank=True,
        null=True,
        help_text=_('其他備註資訊')
    )
    
    class Meta:
        verbose_name = _('診所醫生')
        verbose_name_plural = _('診所醫生')
        ordering = ['-create_time']
        indexes = [
            models.Index(fields=['clinic']),
            models.Index(fields=['user']),
            models.Index(fields=['is_active']),
            models.Index(fields=['clinic', 'is_active']),  # 複合索引，用於查詢診所的啟用醫生
        ]
        # 確保同一診所內醫生姓名不重複（可選，根據業務需求調整）
        # unique_together = [['clinic', 'name']]
    
    def __str__(self):
        clinic_name = self.clinic.name if self.clinic else 'Unknown'
        return f'{self.name} - {clinic_name}'


class CertificateApplication(BaseModel):
    """
    證書申請 Model
    
    存儲證書申請的相關資訊，包括診所資訊、表單資料、驗證 token 等。
    """
    
    # 用戶資訊（會員）
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        verbose_name=_('用戶'),
        related_name='certificate_applications',
        help_text=_('申請證書的用戶（會員）')
    )
    
    # 診所資訊
    clinic = models.ForeignKey(
        Clinic,
        on_delete=models.CASCADE,
        verbose_name=_('診所'),
        related_name='certificate_applications',
        help_text=_('證書所屬的診所（主要診所）')
    )
    
    consultation_clinic = models.ForeignKey(
        Clinic,
        on_delete=models.SET_NULL,
        verbose_name=_('諮詢診所'),
        related_name='consultation_certificate_applications',
        blank=True,
        null=True,
        help_text=_('諮詢診所')
    )
    
    surgeon_name = models.CharField(
        max_length=255,
        verbose_name=_('手術醫師'),
        blank=True,
        null=True,
        help_text=_('手術醫師姓名')
    )
    
    consultant_name = models.CharField(
        max_length=255,
        verbose_name=_('諮詢師'),
        blank=True,
        null=True,
        help_text=_('諮詢師姓名')
    )
    
    # 證書資料（JSON 格式存儲）
    certificate_data = models.JSONField(
        verbose_name=_('證書資料'),
        default=dict,
        help_text=_('存儲證書相關的表單資料，包含 email 和 tx- 開頭的欄位')
    )
    
    # 驗證相關
    verification_token = models.CharField(
        max_length=64,
        unique=True,
        verbose_name=_('驗證 Token'),
        help_text=_('用於驗證 email 的 token')
    )
    token_expires_at = models.DateTimeField(
        verbose_name=_('Token 過期時間'),
        help_text=_('驗證 token 的過期時間')
    )
    verified_at = models.DateTimeField(
        verbose_name=_('驗證時間'),
        blank=True,
        null=True,
        help_text=_('email 驗證完成的時間')
    )
    
    # 狀態
    status = models.CharField(
        max_length=20,
        choices=CertificateApplicationStatus.CHOICES,
        default=CertificateApplicationStatus.PENDING,
        verbose_name=_('狀態')
    )
    
    # 發證相關
    certificate_group_id = models.IntegerField(
        verbose_name=_('證書群組 ID'),
        blank=True,
        null=True,
        help_text=_('發證成功後返回的證書群組 ID')
    )
    
    certificate_hash = models.CharField(
        max_length=255,
        verbose_name=_('證書 Hash'),
        blank=True,
        null=True,
        help_text=_('證書完成發證後返回的 hash 值')
    )

    # 發證時間
    issued_at = models.DateTimeField(
        verbose_name=_('發證時間'),
        blank=True,
        null=True,
        help_text=_('證書發放完成的時間')
    )
    
    class Meta:
        verbose_name = _('證書申請')
        verbose_name_plural = _('證書申請')
        ordering = ['-create_time']
        indexes = [
            models.Index(fields=['verification_token']),
            models.Index(fields=['status']),
            models.Index(fields=['user']),
            models.Index(fields=['clinic']),
            models.Index(fields=['user', 'clinic']),  # 複合索引，用於查詢用戶在某診所的證書
        ]
    
    def generate_verification_token(self):
        """
        生成驗證 token
        
        Returns:
            str: 生成的 token
        """
        token = secrets.token_urlsafe(32)
        self.verification_token = token
        # Token 有效期 7 天
        self.token_expires_at = timezone.now() + timedelta(days=7)
        return token
    
    def is_token_valid(self):
        """
        檢查 token 是否有效（未過期且未使用）
        
        Returns:
            bool: token 是否有效
        """
        # 如果已經發證，則無效
        if self.status == CertificateApplicationStatus.ISSUED:
            return False
        
        # 檢查是否過期
        if self.token_expires_at and timezone.now() > self.token_expires_at:
            # 自動標記為過期
            if self.status != CertificateApplicationStatus.EXPIRED:
                self.status = CertificateApplicationStatus.EXPIRED
                self.save(update_fields=['status'])
            return False
        
        return True
    
    def mark_as_verified(self):
        """
        標記為已驗證
        """
        self.status = CertificateApplicationStatus.VERIFIED
        self.verified_at = timezone.now()
        self.save()
    
    def mark_as_issued(self, certificate_group_id, certificate_hash=None):
        """
        標記為已發證
        
        Args:
            certificate_group_id: 證書群組 ID
            certificate_hash: 證書 hash 值（可選）
        """
        self.status = CertificateApplicationStatus.ISSUED
        self.certificate_group_id = certificate_group_id
        if certificate_hash:
            self.certificate_hash = certificate_hash
        self.issued_at = timezone.now()
        self.save()
    
    def get_applicant_name(self):
        """
        獲取申請人姓名（從用戶獲取）
        """
        if self.user:
            return self.user.get_full_name() or self.user.username
        return 'Unknown'
    
    def get_applicant_email(self):
        """
        獲取申請人電子郵件（從用戶獲取）
        """
        if self.user:
            return self.user.email
        return None
    
    def get_applicant_phone(self):
        """
        獲取申請人電話（從用戶獲取）
        """
        if self.user:
            return self.user.phone_number
        return None
    
    def __str__(self):
        applicant_name = self.get_applicant_name()
        return f'{applicant_name} - {self.clinic.name} ({self.get_status_display()})'
