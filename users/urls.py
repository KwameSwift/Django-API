from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('verify-email/', views.EmailVerifyView.as_view(), name='verify-email'),
    path('token-refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('login', views.LoginView.as_view(), name='login'),
    path('reset-password-confirm/<uidb64>/<token>/',
         views.PasswordTokenCheckView.as_view(), name='reset-password-confirm'),
    path('set-new-password', views.SetNewPasswordView.as_view(), name='set-new-password'),
]
