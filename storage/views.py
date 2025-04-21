from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.conf import settings
from django.contrib import messages
from .forms import LoginForm, FileUploadForm
from .models import File, Folder
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.contrib.auth import logout
from rest_framework_simplejwt.tokens import RefreshToken
import boto3
import uuid
from .forms import RegisterForm
from django.contrib.auth import login as auth_login
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode
import io
from django.http import HttpResponse
import qrcode
import qrcode.image.pil
from django_otp import login as otp_login
from base64 import b64encode

@login_required
def mfa_setup(request):
    user = request.user

    # Create or retrieve unconfirmed TOTP device
    device, created = TOTPDevice.objects.get_or_create(user=user, name='default', confirmed=False)

    if not device.confirmed:
        otp_uri = device.config_url

        # Use PIL to generate a real image we can encode
        factory = qrcode.image.pil.PilImage
        img = qrcode.make(otp_uri, image_factory=factory)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")  # This now works with Pillow
        qr_image_base64 = b64encode(buffer.getvalue()).decode()

        return render(request, 'storage/mfa_setup.html', {'qr_code_base64': qr_image_base64})

    return redirect('profile')


@login_required
def profile(request):
    mfa_status = "Enabled" if request.user.is_mfa_enabled else "Disabled"
    return render(request, 'storage/profile.html', {'mfa_status': mfa_status})

from django.contrib import messages

@login_required
def disable_mfa(request):
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
    if request.method == "POST":
        token = request.POST.get("token")

        # Get the user's unconfirmed MFA device
        device = TOTPDevice.objects.filter(user=request.user, name='default').first()

        if device and device.verify_token(token):
            # ✅ Mark as confirmed if not already
            if not device.confirmed:
                device.confirmed = True
                device.save()

            # ✅ Let django-otp know this device is verified for this session
            otp_login(request, device)

            request.user.is_mfa_enabled = True
            request.user.save()

            messages.success(request, "MFA verification successful.")
            return redirect('profile')
        else:
            messages.error(request, "Invalid token. Try again.")

    return render(request, 'storage/mfa_verify.html')


def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            # Optional: log user in directly after registration
            auth_login(request, user)

            # Generate JWT and store in session
            refresh = RefreshToken.for_user(user)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)

            return redirect('dashboard')
    else:
        form = RegisterForm()

    return render(request, 'storage/register.html', {'form': form})

# S3 Upload Helper
def upload_to_s3(file, s3_key):
    s3 = boto3.client('s3')
    s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, s3_key)
    return s3_key


# Login View
def user_login(request):
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)

            return redirect('dashboard')  # Change this to your dashboard URL name
        else:
            messages.error(request, "Invalid credentials")
    else:
        form = LoginForm()
    return render(request, 'storage/login.html', {'form': form})


# File Upload View
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file_obj = request.FILES['file_obj']
            file_name = form.cleaned_data['file_name']
            folder = form.cleaned_data.get('folder')
            shared_with = form.cleaned_data.get('shared_with')
            is_public = form.cleaned_data.get('is_public')

            # S3 key pattern
            s3_key = f"{request.user.id}/{folder.name if folder else 'root'}/{uuid.uuid4()}_{file_obj.name}"
            upload_to_s3(file_obj, s3_key)

            file_instance = File.objects.create(
                file_name=file_name,
                s3_key=s3_key,
                uploaded_by=request.user,
                folder=folder,
                is_public=is_public,
            )

            if shared_with:
                file_instance.shared_with.set(shared_with)

            messages.success(request, "File uploaded successfully.")
            return redirect('upload_file')
    else:
        form = FileUploadForm()
    return render(request, 'storage/upload_file.html', {'form': form})

@login_required
def dashboard(request):
    user = request.user

    # Show files the user owns or are shared with them or public
    files = File.objects.filter(
        Q(uploaded_by=user) |
        Q(shared_with=user) |
        Q(is_public=True)
    ).distinct()

    return render(request, 'storage/dashboard.html', {'files': files})

def user_logout(request):
    # Remove JWT tokens from session
    request.session.pop('access_token', None)
    request.session.pop('refresh_token', None)
    logout(request)
    return redirect('login')