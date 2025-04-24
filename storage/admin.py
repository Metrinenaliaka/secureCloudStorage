from django.contrib import admin
from .models import File, Folder, User, AuditLog

admin.site.register(File)
admin.site.register(Folder)
admin.site.register(User)
admin.site.register(AuditLog)

# Register your models here.
