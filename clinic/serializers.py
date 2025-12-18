"""
Serializers for Clinic and Certificate Application models.
"""

from rest_framework import serializers
from users.models import User
from users.serializers import UserSerializer
from clinic.models import Clinic, CertificateApplication, Doctor, ClinicUserPermission


class ClinicSerializer(serializers.ModelSerializer):
    """
    Serializer for Clinic model.
    """
    
    class Meta:
        model = Clinic
        fields = '__all__'
        read_only_fields = ['id']


class CertificateApplicationCreateSerializer(serializers.Serializer):
    """
    Serializer for creating a certificate application.
    """
    user_id = serializers.IntegerField(
        required=True,
        help_text='用戶 ID（會員 ID）'
    )
    clinic_id = serializers.IntegerField(
        required=True,
        help_text='診所 ID'
    )
    certificate_data = serializers.DictField(
        required=True,
        help_text='證書資料，必須包含 email 欄位，可選包含 tx- 開頭的模板欄位值'
    )


class CertificateApplicationSerializer(serializers.ModelSerializer):
    """
    Serializer for CertificateApplication model.
    """
    clinic = ClinicSerializer(read_only=True)
    clinic_id = serializers.IntegerField(write_only=True, required=False)
    consultation_clinic = ClinicSerializer(read_only=True)
    consultation_clinic_id = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    user_id = serializers.IntegerField(write_only=True, required=False)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_username = serializers.CharField(source='user.username', read_only=True)
    applicant_name = serializers.SerializerMethodField(help_text='申請人姓名（從用戶獲取）')
    applicant_email = serializers.SerializerMethodField(help_text='申請人電子郵件（從用戶獲取）')
    applicant_phone = serializers.SerializerMethodField(help_text='申請人電話（從用戶獲取）')
    
    class Meta:
        model = CertificateApplication
        fields = [
            'id',
            'user',
            'user_id',
            'user_email',
            'user_username',
            'clinic',
            'clinic_id',
            'consultation_clinic',
            'consultation_clinic_id',
            'surgeon_name',
            'surgery_date',
            'consultant_name',
            'certificate_number',
            'applicant_name',
            'applicant_email',
            'applicant_phone',
            'certificate_data',
            'status',
            'verification_token',
            'token_expires_at',
            'verified_at',
            'certificate_group_id',
            'certificate_hash',
            'issued_at',
            'create_time',
            'update_time',
        ]
        read_only_fields = [
            'id',
            'user',
            'user_email',
            'user_username',
            # 注意：applicant_name, applicant_email, applicant_phone 是 SerializerMethodField，
            # 它們本身就是只讀的，不需要在 read_only_fields 中
            'certificate_number',  # 認證序號由系統自動生成，只讀
            'verification_token',
            'token_expires_at',
            'verified_at',
            'certificate_group_id',
            'certificate_hash',
            'issued_at',
            'create_time',
            'update_time',
        ]
    
    def get_applicant_name(self, obj) -> str:
        """從用戶獲取申請人姓名"""
        return obj.get_applicant_name() or ''
    
    def get_applicant_email(self, obj) -> str:
        """從用戶獲取申請人電子郵件"""
        return obj.get_applicant_email() or ''
    
    def get_applicant_phone(self, obj) -> str:
        """從用戶獲取申請人電話"""
        return obj.get_applicant_phone() or ''
    
    def validate_clinic_id(self, value):
        """驗證診所是否存在"""
        if value and not Clinic.objects.filter(id=value).exists():
            raise serializers.ValidationError("診所不存在")
        return value
    
    def validate_consultation_clinic_id(self, value):
        """驗證諮詢診所是否存在"""
        if value and not Clinic.objects.filter(id=value).exists():
            raise serializers.ValidationError("諮詢診所不存在")
        return value


class CertificateVerificationSerializer(serializers.Serializer):
    """
    Serializer for verifying certificate application token.
    """
    token = serializers.CharField(
        required=True,
        help_text='驗證 token'
    )


class DoctorSerializer(serializers.ModelSerializer):
    """
    Serializer for Doctor model.
    """
    clinic = ClinicSerializer(read_only=True)
    clinic_id = serializers.IntegerField(write_only=True, required=False, help_text='診所 ID')
    user_id = serializers.IntegerField(write_only=True, required=False, allow_null=True, help_text='用戶 ID（可選）')
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = Doctor
        fields = [
            'id',
            'clinic',
            'clinic_id',
            'user',
            'user_id',
            'user_email',
            'user_username',
            'name',
            'email',
            'phone',
            'license_number',
            'specialty',
            'title',
            'is_active',
            'notes',
            'create_time',
            'update_time',
        ]
        read_only_fields = [
            'id',
            'clinic',
            'user',
            'user_email',
            'user_username',
            'create_time',
            'update_time',
        ]
    
    def validate_clinic_id(self, value):
        """驗證診所是否存在"""
        if not Clinic.objects.filter(id=value).exists():
            raise serializers.ValidationError("診所不存在")
        return value
    
    def validate_user_id(self, value):
        """驗證用戶是否存在（如果提供了 user_id）"""
        if value is not None and not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("用戶不存在")
        return value


class ClinicUserPermissionSerializer(serializers.ModelSerializer):
    """
    Serializer for ClinicUserPermission model.
    """
    clinic = ClinicSerializer(read_only=True)
    clinic_id = serializers.IntegerField(write_only=True, required=False, help_text='診所 ID')
    user = UserSerializer(read_only=True)
    user_id = serializers.IntegerField(write_only=True, required=False, help_text='用戶 ID')
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = ClinicUserPermission
        fields = [
            'id',
            'clinic',
            'clinic_id',
            'user',
            'user_id',
            'user_email',
            'user_username',
            'create_time',
            'update_time',
        ]
        read_only_fields = [
            'id',
            'clinic',
            'user',
            'user_email',
            'user_username',
            'create_time',
            'update_time',
        ]
    
    def validate_clinic_id(self, value):
        """驗證診所是否存在"""
        if not Clinic.objects.filter(id=value).exists():
            raise serializers.ValidationError("診所不存在")
        return value
    
    def validate_user_id(self, value):
        """驗證用戶是否存在"""
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("用戶不存在")
        return value

