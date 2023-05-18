from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    salt = models.BinaryField(editable=True)
    encrypted_main_key = models.TextField()
