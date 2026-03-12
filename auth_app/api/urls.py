from django.urls import path
from .views import (
    RegistrationView, 
    ActivationView, 
    LoginView, 
    LogoutView, 
    TokenRefreshView, 
    PasswordResetView,
    PasswordResetConfirmSerializer
)

urlpatterns = [
    path('api/register/', RegistrationView.as_view(), name='registration'),
    path('api/activate/<str:uidb64>/<str:token>/', ActivationView.as_view(), name='activate'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('api/password_confirm/<str:uidb64>/<str:token>', PasswordResetConfirmSerializer.as_view(), name='password_reset_confirm')
]