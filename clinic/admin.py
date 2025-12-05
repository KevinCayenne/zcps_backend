from django.contrib import admin
from clinic.models import Clinic, Doctor, ClinicUserPermission

admin.site.register(Clinic)
admin.site.register(Doctor)
admin.site.register(ClinicUserPermission)