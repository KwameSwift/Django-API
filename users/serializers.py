from rest_framework import serializers
from . import views
from .models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerifySerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(
        max_length=56, min_length=8, write_only=True)
    username = serializers.CharField(
        max_length=56, min_length=8, read_only=True)
    tokens = serializers.CharField(
        max_length=255, min_length=8, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']


class RequestPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=233)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=255)
    uidb64 = serializers.CharField(max_length=255)
    token = serializers.CharField(max_length=255)

    class Meta:
        fields = ['password', 'uidb64', 'token']
