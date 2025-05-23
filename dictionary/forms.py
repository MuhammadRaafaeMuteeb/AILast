from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Tool

class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

class SigninForm(AuthenticationForm):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class ToolForm(forms.ModelForm):
    class Meta:
        model = Tool
        fields = ['name', 'link', 'description', 'developer', 'category']

class MultiFileInput(forms.FileInput):
    allow_multiple_selected = True

    def value_from_datadict(self, data, files, name):
        if not files:
            return None
        return files.getlist(name)

class MultipleCSVUploadForm(forms.Form):
    csv_files = forms.FileField(
        widget=MultiFileInput(attrs={'multiple': True}),
        label="Upload one or more CSV files"
    )
