from django.contrib import admin
from clinic.models import Clinic, Doctor, ClinicUserPermission, CertificateApplication


admin.site.register(Clinic)
admin.site.register(Doctor)
admin.site.register(ClinicUserPermission)
admin.site.register(CertificateApplication)
