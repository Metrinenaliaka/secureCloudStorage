from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid

# User Model
class User(AbstractUser):
    """
    Custom User model to extend the default Django user model.
    This model includes additional fields for multi-factor authentication (MFA)
    and user roles (e.g., admin, user).
    The user is identified by a UUID.
    The username is unique and used for authentication.
    The password is hashed and stored securely.
    The email is used for notifications and password recovery.
    The user can have multiple folders and files associated with them.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    is_mfa_enabled = models.BooleanField(default=False)
    role = models.CharField(max_length=50, default='user')  # e.g., admin, user

    def __str__(self):
        return self.username


# Folder Model
class Folder(models.Model):
    """	
    Model to represent folders in the file storage system.
    Each folder is associated with a user and can contain subfolders.
    The folder is identified by a UUID.
    The folder can be shared with other users.
    The folder is created with a timestamp.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='folders')
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='subfolders')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


# File Model
class File(models.Model):
    """
    Model to represent files uploaded by users.
    Each file is associated with a user and can belong to a folder.
    The file is stored in S3 with a unique key.
    The file name is stored for reference.
    The file can be encrypted, and access control is managed through public/private settings.
    The file can be shared with other users.
    The file is associated with an audit log to track user actions.
    The file is identified by a UUID.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file_name = models.CharField(max_length=255)
    s3_key = models.CharField(max_length=1024)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    folder = models.ForeignKey('Folder', on_delete=models.SET_NULL, null=True, blank=True, related_name='files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_encrypted = models.BooleanField(default=True)

    # 🔐 Access Control
    is_public = models.BooleanField(default=False)
    shared_with = models.ManyToManyField(User, related_name='shared_files', blank=True)

    class Meta:
        unique_together = ('uploaded_by', 'folder', 'file_name')

    def __str__(self):
        return self.file_name

class AuditLog(models.Model):
    """
    Model to log user actions on files and folders.
    This includes actions like upload, download, delete, share, permission change, and rename.
    Each action is associated with a user and a file or folder.
    """
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

