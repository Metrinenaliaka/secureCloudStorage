from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.contrib.auth import login as auth_login
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import login as otp_login
from rest_framework_simplejwt.tokens import RefreshToken
from botocore.client import Config
from django.http import HttpResponse
from django.utils import timezone
from django.utils.timezone import now 


import boto3
import uuid
import io
import os
from io import BytesIO
import qrcode
import qrcode.image.pil
from base64 import b64encode
import logging
import mimetypes
from django.http import FileResponse

logger = logging.getLogger(__name__)

from .forms import LoginForm, FileUploadForm, RegisterForm, ShareFileForm
from .models import File, FilePermission
from .utils import log_file_action, decrypt_file_bytes, encrypt_file_bytes

# ---------- MFA SETUP ----------
@login_required
def mfa_setup(request):
    """
    A view to set up MFA for the user. It generates a QR code
    for the user to scan with their TOTP app. The QR code is
    generated using the TOTPDevice model from django_otp.
    """	
    user = request.user
    device, created = TOTPDevice.objects.get_or_create(user=user, name='default', confirmed=False)

    if not device.confirmed:
        otp_uri = device.config_url
        factory = qrcode.image.pil.PilImage
        img = qrcode.make(otp_uri, image_factory=factory)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_image_base64 = b64encode(buffer.getvalue()).decode()

        return render(request, 'storage/mfa_setup.html', {'qr_code_base64': qr_image_base64})

    return redirect('profile')

@login_required
def reset_mfa_device(request):
    """	
    A view to reset the MFA device for the user. It deletes
    the existing TOTPDevice and allows the user to re-enroll.
    This is useful if the user has lost access to their TOTP
    app or needs to reset their MFA settings.
    """
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        request.user.is_mfa_enabled = False
        request.user.save()
        messages.success(request, "MFA device reset. You can now re-enroll.")
        return redirect('mfa_setup')

    return render(request, 'storage/reset_mfa.html')

@login_required
def disable_mfa(request):
    """	
    A view to disable MFA for the user. It deletes the
    existing TOTPDevice and updates the user's MFA status.
    This is useful if the user no longer wants to use MFA
    or needs to disable it for any reason.
    """	
    if request.method == 'POST':
        devices = TOTPDevice.objects.filter(user=request.user, confirmed=True)
        devices.delete()
        request.user.is_mfa_enabled = False
        request.user.save()
        messages.success(request, "MFA has been disabled.")
        return redirect('profile')
    return render(request, 'storage/disable_mfa.html')

@login_required
def mfa_verify(request):
    """
    A view to verify the MFA token entered by the user.
    It checks the token against the TOTPDevice and logs in
    the user if the token is valid. This is used during
    the login process to ensure that the user has access
    to their MFA device.
    """
    if request.method == "POST":
        token = request.POST.get("token")
        device = TOTPDevice.objects.filter(user=request.user, name='default').first()

        if device and device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                device.save()
            otp_login(request, device)
            request.user.is_mfa_enabled = True
            request.user.save()
            messages.success(request, "MFA verification successful.")
            return redirect('profile')
        else:
            messages.error(request, "Invalid token. Try again.")
    return render(request, 'storage/mfa_verify.html')

# ---------- USER AUTH ----------
def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.generate_encryption_key()  # 🔐 Generate E2EE key
            auth_login(request, user)
            refresh = RefreshToken.for_user(user)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)
            return redirect('dashboard')
    else:
        form = RegisterForm()
    return render(request, 'storage/register.html', {'form': form})


def user_login(request):
    """
    A view to handle user login. It uses the built-in
    AuthenticationForm from Django to authenticate the user.
    If the user is authenticated, it logs them in and
    redirects them to the dashboard. If the user is not
    authenticated, it shows an error message.
    """ 
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            refresh = RefreshToken.for_user(user)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials")
    else:
        form = LoginForm()
    return render(request, 'storage/login.html', {'form': form})

def user_logout(request):
    """
    A view to handle user logout. It clears the session
    and logs the user out. It also deletes the access
    and refresh tokens from the session. After logging out,
    it redirects the user to the login page.
    """
    request.session.pop('access_token', None)
    request.session.pop('refresh_token', None)
    logout(request)
    return redirect('login')

# ---------- PROFILE & DASHBOARD ----------
@login_required
def profile(request):
    """
    A view to display the user's profile. It shows the
    user's MFA status and a list of files uploaded by
    the user. The profile page also allows the user to
    manage their MFA settings and view their uploaded files.
    """
    mfa_status = "Enabled" if request.user.is_mfa_enabled else "Disabled"
    files = File.objects.filter(uploaded_by=request.user)
    return render(request, 'storage/profile.html', {'mfa_status': mfa_status, 'files': files})

@login_required
def dashboard(request):
    """
    Displays user files (uploaded, shared, or public) and supports file search by name.
    """
    user = request.user
    query = request.GET.get('q', '')

    files = File.objects.filter(
        Q(uploaded_by=user) | Q(shared_with=user) | Q(is_public=True),
        deleted_at__isnull=True
    ).distinct()

    if query:
        files = files.filter(file_name__icontains=query)

    return render(request, 'storage/dashboard.html', {'files': files, 'query': query})

# ---------- FILE HANDLING ----------
def upload_to_s3(file, s3_key):
    """
    Uploads a file to S3 using the provided S3 key.
    The file is uploaded to the S3 bucket specified in
    the settings. The S3 key is a unique identifier for
    the file in the S3 bucket. The function uses the
    boto3 library to interact with the S3 service.
    """
    s3 = boto3.client(
        's3',
        region_name=settings.AWS_REGION,
        config=Config(signature_version='s3v4')
        )
    s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, s3_key)
    return s3_key



@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file_obj = request.FILES['file_obj']
            file_name = form.cleaned_data['file_name']
            folder = form.cleaned_data.get('folder')
            is_public = form.cleaned_data.get('is_public')

            file_bytes = file_obj.read()
            encrypted_bytes = encrypt_file_bytes(file_bytes, request.user.encryption_key)
            print(f"Encrypted preview (upload): {encrypted_bytes[:60]}")
            print(f"Original preview: {file_bytes[:60]}")

            encrypted_file = BytesIO(encrypted_bytes)

            s3_key = f"{request.user.id}/{folder.name if folder else 'root'}/{uuid.uuid4()}_{file_obj.name}"
            upload_to_s3(encrypted_file, s3_key)

            file_instance = File.objects.create(
                file_name=file_name,
                s3_key=s3_key,
                uploaded_by=request.user,
                folder=folder,
                is_public=is_public,
                is_encrypted=True,
            )           

            log_file_action(request.user, file_instance, 'UPLOAD', request)
            messages.success(request, "File uploaded securely with E2EE.")
            return redirect('upload_file')
    else:
        form = FileUploadForm()
    return render(request, 'storage/upload_file.html', {'form': form})

# ---------- SECURE ACTIONS (OTP-Protected Delete & Download) ----------
def generate_presigned_url(s3_key, expiration=300):
    """
    Generates a presigned URL for downloading a file from S3.
    The URL is valid for a specified duration (default is
    5 minutes). The presigned URL allows the user to download
    the file without needing to authenticate with AWS. The
    function uses the boto3 library to generate the URL.
    """
    s3 = boto3.client(
        's3',
        region_name=settings.AWS_REGION,
        config=Config(signature_version='s3v4')
    )

    return s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': s3_key},
        ExpiresIn=expiration
    )

@login_required
def verify_action_otp(request, file_id, action):
    """
    Step 1: Ensure the user owns or was shared the file.
    Step 2: Render OTP form; on POST verify, then redirect to secure_file_action.
    """
    user = request.user

    # 1️⃣ Allow owner or any shared user
    try:
        file = File.objects.get(
            Q(id=file_id) &
            (Q(uploaded_by=user) | Q(shared_with=user))
        )
    except File.DoesNotExist:
        return HttpResponse("You do not have access to this file.", status=403)

    # 2️⃣ On POST, check OTP
    if request.method == "POST":
        token = request.POST.get("token")
        device = TOTPDevice.objects.filter(user=user, confirmed=True).first()

        if device and device.verify_token(token):
            request.session['verified_file_action'] = f"{file_id}:{action}"
            request.session.set_expiry(300)
            return redirect('secure_file_action', file_id=file.id, action=action)
        else:
            log_file_action(user, file, f'{action.upper()}_FAILED_OTP', request)
            messages.error(request, "Invalid OTP code.")

    return render(request, 'storage/verify_action_otp.html', {
        'file': file,
        'action': action,
    })


@login_required
def secure_file_action(request, file_id, action):
    """
    Executes download/delete/restore/share only if:
      • user is owner, OR
      • user was shared and holds the matching permission.
    """
    user = request.user

    # 1️⃣ Fetch file if owner or shared
    file = get_object_or_404(
        File,
        Q(id=file_id) &
        (Q(uploaded_by=user) | Q(shared_with=user))
    )

    # 2️⃣ Check OTP step was done
    expected = f"{file_id}:{action}"
    if request.session.get('verified_file_action') != expected:
        return redirect('verify_action_otp', file_id=file_id, action=action)

    # 3️⃣ OWNER flag
    is_owner = (file.uploaded_by == user)

    # 4️⃣ PERMISSION CHECK for non-owners
    if not is_owner:
        try:
            perm = FilePermission.objects.get(file=file, user=user)
        except FilePermission.DoesNotExist:
            return HttpResponse("You don't have permission to access this file.", status=403)

        # map actions → required permission
        if action == 'download' and perm.permission not in ['download', 'edit']:
            return HttpResponse("You don't have download permission.", status=403)
        if action == 'share' and perm.permission != 'edit':
            return HttpResponse("Only owners can re-share files.", status=403)
        if action in ['delete', 'restore'] and not is_owner:
            return HttpResponse("Only owners can delete or restore files.", status=403)

    # 5️⃣ EXECUTE ACTION
    if action == 'download':
        # download logic
        s3 = boto3.client(
            's3',
            region_name=settings.AWS_REGION,
            config=Config(signature_version='s3v4')
        )
        obj = s3.get_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=file.s3_key)
        encrypted_bytes = obj['Body'].read()

        # 🔑 Use the owner's key, not request.user's key
        owner_key = file.uploaded_by.encryption_key
        if not owner_key:
            return HttpResponse("Owner's encryption key is missing.", status=500)

        try:
            decrypted_bytes = decrypt_file_bytes(encrypted_bytes, owner_key)
        except Exception as e:
            return HttpResponse(f"Decryption failed: {e}", status=403)

        # Serve the decrypted data
        stream = BytesIO(decrypted_bytes)
        filename = os.path.basename(file.s3_key).split('_', 1)[-1]
        mime_type, _ = mimetypes.guess_type(filename)
        response = FileResponse(stream, content_type=(mime_type or 'application/octet-stream'))
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        log_file_action(request.user, file, 'DOWNLOAD', request)
        return response

    elif action == 'delete':
        # soft or permanent delete
        if not file.is_deleted:
            file.is_deleted = True
            file.deleted_at = timezone.now()
            file.save()
            log_file_action(user, file, 'SOFT_DELETE', request)
            messages.success(request, f"{file.file_name} moved to trash.")
        else:
            s3 = boto3.client(
                's3',
                region_name=settings.AWS_REGION,
                config=Config(signature_version='s3v4')
            )
            s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=file.s3_key)
            file.delete()
            log_file_action(user, file, 'PERMANENT_DELETE', request)
            messages.success(request, f"{file.file_name} permanently deleted.")
        return redirect('profile')

    elif action == 'restore':
        if file.is_deleted:
            file.is_deleted = False
            file.deleted_at = None
            file.save()
            log_file_action(user, file, 'RESTORE', request)
            messages.success(request, f"{file.file_name} restored.")
        else:
            messages.warning(request, "File is not in trash.")
        return redirect('profile')

    elif action == 'share':
        # re-share form (owners only)
        if request.method == 'POST':
            form = ShareFileForm(request.POST)
            if form.is_valid():
                users = form.cleaned_data['users']
                permission = form.cleaned_data['permission']
                file.shared_with.set(users)
                FilePermission.objects.filter(file=file).delete()
                for u in users:
                    FilePermission.objects.create(file=file, user=u, permission=permission)
                log_file_action(user, file, 'SHARE', request)
                del request.session['verified_file_action']
                messages.success(request, "File shared successfully.")
                return redirect('dashboard')
        else:
            shared = file.shared_with.all()
            form = ShareFileForm(initial={'users': shared})

        return render(request, 'storage/share_file.html', {'form': form, 'file': file})

    return HttpResponse("Invalid action.", status=400)
# @login_required
# def share_file(request, file_id):
#     expected = f"{file_id}:share"
#     if request.session.get('verified_file_action') != expected:
#         return redirect('verify_action_otp', file_id=file_id, action='share')

#     print("✅ Inside share_file view (OTP Verified)")

#     file = get_object_or_404(File, id=file_id, uploaded_by=request.user)

#     if request.method == 'POST':
#         form = ShareFileForm(request.POST)
#         if form.is_valid():
#             users = form.cleaned_data['users']
#             permission = form.cleaned_data.get('permission')


#             file.shared_with.set(users)
#             FilePermission.objects.filter(file=file).delete()

#             for user in users:
#                 FilePermission.objects.create(file=file, user=user, permission=permission)
#             log_file_action(request.user, file, 'SHARE', request)
#             messages.success(request, "File shared successfully.")
#             return redirect('dashboard')
#     else:
#         try:
#             shared_users = file.shared_with.all()
#             form = ShareFileForm(initial={'users': shared_users})
#         except Exception as e:
#             print(f"❌ Error initializing ShareFileForm: {e}")
#             form = ShareFileForm()  # fallback to blank form

#     return render(request, 'storage/share_file.html', {'form': form, 'file': file})

@login_required
def soft_delete_file(request, file_id):
    file = get_object_or_404(File, id=file_id, uploaded_by=request.user, is_deleted=False)
    file.is_deleted = True
    file.deleted_at = timezone.now()
    file.save()
    log_file_action(request.user, file, 'SOFT_DELETE', request)
    messages.success(request, f"{file.file_name} moved to trash.")
    return redirect('profile')
