from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('upload/', views.upload_file, name='upload_file'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('register/', views.register, name='register'),
    path('profile/', views.profile, name='profile'),
    path('mfa/setup/', views.mfa_setup, name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify, name='mfa_verify'),
    path('mfa/disable/', views.disable_mfa, name='disable_mfa'),
    path('mfa/reset/', views.reset_mfa_device, name='reset_mfa_device'),
    path('file/<uuid:file_id>/<str:action>/', views.secure_file_action, name='secure_file_action'),
    path('file/<uuid:file_id>/<str:action>/verify/', views.verify_action_otp, name='verify_action_otp'),
    # path('file/<uuid:file_id>/share/', views.share_file, name='share_file'),


]
