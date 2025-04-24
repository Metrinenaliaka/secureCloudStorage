from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from .models import File, FilePermission
from django.contrib.auth import get_user_model

User = get_user_model()

class RegisterForm(UserCreationForm):
    """
    A form for creating new users. Includes all the required
    fields, plus a repeated password.
    """	
    email = forms.EmailField(required=True, label='Email Address')

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email is already registered.")
        return email


# Login Form
class LoginForm(AuthenticationForm):
    """
    A form that authenticates users. It uses the built-in
    AuthenticationForm from Django
    """
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

# File Upload Form
class FileUploadForm(forms.ModelForm):
    """
    A form for uploading files. It includes fields for the
    file name, folder, file object, and sharing options.
    """
    file_obj = forms.FileField(label="Select file")
    class Meta:
        model = File
        fields = ['file_name', 'folder', 'file_obj', 'is_public']


class ShareFileForm(forms.Form):
    users = forms.ModelMultipleChoiceField(queryset=User.objects.all(), widget=forms.CheckboxSelectMultiple)
    permission = forms.ChoiceField(choices=FilePermission.PERMISSION_CHOICES)