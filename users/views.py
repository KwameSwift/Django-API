from django.shortcuts import render
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from . import serializers
from .models import User, Profile
from rest_framework import generics, mixins
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse
from rest_framework import views
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
# from .renderers import UserRenderer
import jwt
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# Create your views here.


# registering a user
class UserRegistrationView(generics.GenericAPIView):
    # get request
    serializer_class = serializers.UserRegistrationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])

            # get the current domain, the reverse link and and reverse url
            current_site = get_current_site(request).domain
            reverse_link = reverse('verify-email')
            token = RefreshToken.for_user(user).access_token
            url = 'http://' + current_site + reverse_link + '?token= ' + str(token)

            # set up email message for the newly creates user
            email_subject = 'Activate your account'
            email_body = 'Hi ' + user.username + ', \nPlease, kindly use the link below to activate your account \n' + url
            to_email = [request.data.get('email'), ]

            email = EmailMessage(subject=email_subject, body=email_body, to=to_email)
            email.send()
            return Response({
                'message': 'User registration successfully',
                'data': user_data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerifyView(views.APIView):
    serializer_class = serializers.EmailVerifySerializer
    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description',
                                           type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')

        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            user.is_verified = True
            user.save()
            return Response({'message': 'User account successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'message': 'Activation Link is expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'message': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = serializers.LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email')
        password = request.data.get('password')
        if serializer.is_valid():
            user = authenticate(email=email, password=password)

            if not user:
                raise AuthenticationFailed('Invalid user credentials, try again')
            if not user.is_active:
                raise AuthenticationFailed('Account disabled, contact admin')
            if not user.is_verified:
                raise AuthenticationFailed('Email is not verified')

            return Response({
                'email': user.email,
                'username': user.username,
                'tokens': user.tokens()
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordReset(generics.GenericAPIView):
    serializer_class = serializers.RequestPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse(
                'reset-password-confirm', kwargs={'uidb64': uidb64, 'token': token})
            url = 'http://' + current_site + relativeLink
            email_body = 'Hi ' + user.username + ',' + \
                         '\nPlease, kindly use this link to reset your password \n' + url
            email_subject = 'Password Reset'
            to_email = [user.email, ]
            email = EmailMessage(subject=email_subject,
                                 body=email_body, to=to_email)
            email.send()

            return Response({
                'success': True,
                'message': 'Password reset email successfully sent'
            }, status=status.HTTP_200_OK)

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordTokenCheckView(generics.GenericAPIView):

    def get(self, request, uidb64, token):

        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_400_BAD_REQUEST)
            return Response({'message': 'Credentials Valid',
                             'uidb64': uidb64,
                             'token': token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            # PasswordResetTokenGenerator().check_token(user)
            return Response({'error': 'Token is not valid, please request a new one'},
                            status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = serializers.SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            try:
                password = request.data.get('password')
                uidb64 = request.data.get('uidb64')
                token = request.data.get('token')
                user_id = smart_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(id=user_id)

                if not PasswordResetTokenGenerator().check_token(user, token):
                    raise AuthenticationFailed('The reset link is invalid')

                user.set_password(password)
                user.save()

                return Response({
                    'message': 'Password reset done successfully'
                }, status=status.HTTP_200_OK)

            except Exception as e:
                raise AuthenticationFailed('The reset link is invalid')

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(generics.GenericAPIView, mixins.UpdateModelMixin,
              mixins.CreateModelMixin, mixins.DestroyModelMixin,
              mixins.RetrieveModelMixin, mixins.ListModelMixin):
    serializer_class = serializers.ProfileSerializer
    queryset = Profile.objects.all()
    lookup_field = 'id'
    # authentication_classes = [TokenAuthentication]
    # permission_classes = [IsAuthenticated]

    def get(self, request, id=None):
        if id:
            return self.retrieve(request)
        return self.list(request)

    def post(self, request, id):
        return self.create(request, id)

    def put(self, request, id):
        return self.update(request, id)

    def delete(self, request, id):
        return self.destroy(request, id)
