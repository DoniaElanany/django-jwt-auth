from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone_number']