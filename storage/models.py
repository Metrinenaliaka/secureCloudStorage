from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid
from cryptography.fernet import Fernet
from django.utils import timezone

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    is_mfa_enabled = models.BooleanField(default=False)
    role = models.CharField(max_length=50, default='user')
    encryption_key = models.BinaryField(null=True, blank=True)

    def __str__(self):
        return self.username

    def generate_encryption_key(self):
        self.encryption_key = Fernet.generate_key()
        self.save()

class Folder(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='folders')
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='subfolders')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class File(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file_name = models.CharField(max_length=255)
    s3_key = models.CharField(max_length=1024)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    folder = models.ForeignKey('Folder', on_delete=models.SET_NULL, null=True, blank=True, related_name='files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_encrypted = models.BooleanField(default=True)
    is_public = models.BooleanField(default=False)
    shared_with = models.ManyToManyField(User, related_name='shared_files', blank=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('uploaded_by', 'folder', 'file_name')

    def __str__(self):
        return self.file_name

class FilePermission(models.Model):
    PERMISSION_CHOICES = [
        ('view', 'View'),
        ('download', 'Download'),
        ('edit', 'Edit'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='permissions')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES)

    class Meta:
        unique_together = ('file', 'user', 'permission')

    def __str__(self):
        return f"{self.user.username} - {self.permission} - {self.file.file_name}"

class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('UPLOAD', 'Upload'),
        ('DOWNLOAD', 'Download'),
        ('DELETE', 'Delete'),
        ('SHARE', 'Share'),
        ('PERMISSION_CHANGE', 'Permission Change'),
        ('RENAME', 'Rename'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.file.file_name}"
