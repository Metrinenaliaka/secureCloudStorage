from .models import AuditLog

def log_file_action(user, file, action, request=None):
    AuditLog.objects.create(
        user=user,
        file=file,
        action=action,
        ip_address=request.META.get('REMOTE_ADDR') if request else None,
        user_agent=request.META.get('HTTP_USER_AGENT', '') if request else None
    )
