from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.


class UserManager(BaseUserManager):

    def create_user(self, email, username, password=None):

        if email is None:
            raise TypeError('Email cannot be empty')

        if username is None:
            raise TypeError('Username cannot be empty')

        user = self.model(
            email=self.normalize_email(email),
            username=username

        )

        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, username, password=None):
        if email is None:
            raise TypeError('Email cannot be empty')

        user = self.create_user(email, username, password)

        is_staff = True
        is_superuser = True

        user.save()

        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        token = RefreshToken.for_user(self)

        return {
            'refresh': str(token),
            'access': str(token.access_token)
        }
