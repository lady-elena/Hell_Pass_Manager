from django import forms


class PasswordGeneratorForm(forms.Form):
    length = forms.IntegerField(label='Length', min_value=8, max_value=20, initial=8)
    include_lower = forms.BooleanField(label='Include Lowercase', required=False, initial=True)
    include_upper = forms.BooleanField(label='Include Uppercase', required=False, initial=True)
    include_digits = forms.BooleanField(label='Include Digits', required=False, initial=True)
    include_special = forms.BooleanField(label='Include Special Characters', required=False, initial=True)


class UserForm(forms.Form):
    service_name = forms.CharField()
    service_url = forms.URLField()
    login = forms.CharField()
    password = forms.PasswordInput()
    totp_secret = forms.CharField()
    notes = forms.CharField()