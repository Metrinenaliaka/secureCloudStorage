from django.shortcuts import redirect
from django.urls import reverse

class EnforceMFAMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user

        if (
            user.is_authenticated and
            hasattr(user, 'is_mfa_enabled') and
            user.is_mfa_enabled and
            not request.user.is_verified() and
            request.path not in [reverse('mfa_verify'), reverse('logout')]
        ):
            return redirect('mfa_verify')

        return self.get_response(request)
