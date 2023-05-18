from django.db import models
from user.models import CustomUser


class Data(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    service_name = models.CharField(max_length=100, blank=False)
    service_url = models.URLField(max_length=100)
    login = models.CharField(max_length=100, blank=False)
    password = models.CharField(max_length=100, blank=False)
    totp_secret = models.CharField(max_length=100, blank=False)
    notes = models.CharField(max_length=1000)



