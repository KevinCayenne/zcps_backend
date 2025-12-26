"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
"""

from django.contrib import admin
from django.urls import path, include
from users.oauth_views import oauth_login, GoogleCallback
from users.twofactor_views import (
    enable_2fa,
    verify_setup_2fa,
    disable_2fa,
    get_2fa_status,
    verify_2fa_login,
    resend_2fa_code,
)
from users.certificate_views import (
    GetTemplateView,
    IssueCertificatesToNewGroupView,
    IssueCertificatesToExistingGroupView,
    IssueCertificatesWithTemplateView,
)
from clinic.views import (
    ClinicViewSet,
    PublicClinicViewSet,
    SubmitCertificateApplicationView,
    VerifyCertificateTokenView,
    IssueCertificateView,
    GetCertificateView,
    GetCertificatePdfView,
    DoctorViewSet,
    ClinicUserPermissionViewSet,
    CertificateApplicationViewSet,
)
from users.views import UserViewSet, ClientUserViewSet, ClientUserOuterViewSet
from logs.views import ActionLogsViewSet
from announcement.views import AnnouncementViewSet, ClientAnnouncementViewSet
from users.jwt_views import (
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    CustomTokenVerifyView,
)
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)
from rest_framework import routers
from django.conf import settings
from django.conf.urls.static import static

router = routers.DefaultRouter()
router.register(r"users", UserViewSet, basename="users")
router.register(r"clients", ClientUserViewSet, basename="clients")
router.register(r"clients_outer", ClientUserOuterViewSet, basename="clients_outer")
router.register(r"clinics", ClinicViewSet, basename="clinics")
router.register(r"public-clinics", PublicClinicViewSet, basename="public-clinics")
router.register(
    r"clinic-permissions", ClinicUserPermissionViewSet, basename="clinic-permissions"
)
router.register(
    r"certificate-applications",
    CertificateApplicationViewSet,
    basename="certificate-applications",
)
router.register(r"logs", ActionLogsViewSet, basename="action_logs")
router.register(r"doctors", DoctorViewSet, basename="doctors")
router.register(r"announcements", AnnouncementViewSet, basename="announcements")
router.register(
    r"client-announcements", ClientAnnouncementViewSet, basename="client-announcements"
)

urlpatterns = [
    path("api/", include(router.urls)),
    path("admin/", admin.site.urls),
    # API Documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    # Allauth URLs (required for OAuth views)
    path("accounts/", include("allauth.urls")),
    # Custom Djoser endpoints with JWT token blacklisting
    path("auth/", include("users.urls")),
    # Custom JWT login endpoint with 2FA support
    path("auth/jwt/create/", CustomTokenObtainPairView.as_view(), name="jwt-create"),
    path("auth/jwt/refresh/", CustomTokenRefreshView.as_view(), name="jwt-refresh"),
    path("auth/jwt/verify/", CustomTokenVerifyView.as_view(), name="jwt-verify"),
    # Custom logout endpoint with token blacklisting (defined in users.urls)
    # LogoutView is now imported in users.urls, accessible via /auth/logout/
    # Google OAuth endpoints
    path("auth/google/", oauth_login, name="google_login"),
    path("auth/google/callback/", GoogleCallback.as_view(), name="google_callback"),
    # Two-Factor Authentication endpoints
    path("auth/2fa/enable/", enable_2fa, name="2fa_enable"),
    path("auth/2fa/enable/verify/", verify_setup_2fa, name="2fa_verify_setup"),
    path("auth/2fa/disable/", disable_2fa, name="2fa_disable"),
    path("auth/2fa/status/", get_2fa_status, name="2fa_status"),
    path("auth/2fa/verify/", verify_2fa_login, name="2fa_verify_login"),
    path("auth/2fa/resend/", resend_2fa_code, name="2fa_resend"),
    # Certificate endpoints
    path(
        "api/certificates/templates/get-template/",
        GetTemplateView.as_view(),
        name="get_template",
    ),
    path(
        "api/certificates/issue-to-new-group/",
        IssueCertificatesToNewGroupView.as_view(),
        name="issue_certificates_to_new_group",
    ),
    path(
        "api/certificates/issue-to-existing-group/",
        IssueCertificatesToExistingGroupView.as_view(),
        name="issue_certificates_to_existing_group",
    ),
    path(
        "api/certificates/issue-with-template/",
        IssueCertificatesWithTemplateView.as_view(),
        name="issue_certificates_with_template",
    ),
    # Certificate application endpoints
    path(
        "api/certificates/submit-application/",
        SubmitCertificateApplicationView.as_view(),
        name="submit_certificate_application",
    ),
    path(
        "api/certificates/verify-token/",
        VerifyCertificateTokenView.as_view(),
        name="verify_certificate_token",
    ),
    path(
        "api/certificates/issue/",
        IssueCertificateView.as_view(),
        name="issue_certificate",
    ),
    # Certificate retrieval endpoints
    path(
        "api/certificates/get-certificate/",
        GetCertificateView.as_view(),
        name="get_certificate",
    ),
    path(
        "api/certificates/get-pdf/",
        GetCertificatePdfView.as_view(),
        name="get_certificate_pdf",
    ),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
