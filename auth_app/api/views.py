from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.middleware.csrf import get_token

from .serializers import RegistrationSerializer, LoginSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
from .utils import send_activation_email, send_password_reset_email

class RegistrationView(APIView):
    
    def _build_user_response(self, user, token):
        return Response({
            'user': {'id': user.id, 'email': user.email},
            'token': token
        }, status=status.HTTP_201_CREATED)

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        send_activation_email(user, uidb64, token)
        return self._build_user_response(user, token)
    
class ActivationView(APIView):
    
    def _decode_uid_and_get_user(self, uidb64):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            return User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return None
    
    def _validate_user_for_activation(self, user):
        if user and user.is_active:
            return False
        return user is not None
    
    def _activate_user(self, user, token):
        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return True
        return False
    
    def _get_validated_user(self, uidb64):
        user = self._decode_uid_and_get_user(uidb64)
        if not user or not self._validate_user_for_activation(user):
            return None
        return user

    def _activation_error(self):
        return Response(
            {'error': 'Aktivierung fehlgeschlagen.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    def get(self, request, uidb64, token):
        user = self._get_validated_user(uidb64)
        if not user:
            return self._activation_error()
        if self._activate_user(user, token):
            return Response(
                {'message': 'Account successfully activated.'},
                status=status.HTTP_200_OK
            )
        return self._activation_error()
    
class LoginView(APIView):
    
    def _set_cookie(self, response, key, value, httponly=True):
        response.set_cookie(
            key=key,
            value=value,
            httponly=httponly,
            secure=True,
            samesite='None',
        )
    
    def _set_authentication_cookies(self, response, refresh, request):
        self._set_cookie(response, 'access_token', str(refresh.access_token))
        self._set_cookie(response, 'refresh_token', str(refresh))
        self._set_cookie(response, 'csrftoken', get_token(request), httponly=False)

    def _build_login_response(self, user, refresh, request):
        response = Response({
            'detail': 'Login successful',
            'user': {'id': user.id, 'username': user.username}
        }, status=status.HTTP_200_OK)
        self._set_authentication_cookies(response, refresh, request)
        return response

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        return self._build_login_response(user, refresh, request)

class LogoutView(APIView):
    
    def _get_and_blacklist_token(self, refresh_token):
        if not refresh_token:
            return None
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return True
        except TokenError:
            return False
    
    def _delete_auth_cookies(self, response):
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        response.delete_cookie('csrftoken')

    def _get_token_error_response(self, result):
        if result is None:
            return Response(
                {'detail': 'Refresh-Token fehlt.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if result is False:
            return Response(
                {'detail': 'Token ist ungültig oder bereits abgelaufen.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        return None

    def _build_logout_response(self):
        response = Response({
            'detail': 'Logout successful! All tokens will be deleted. Refresh token is now invalid.'
        }, status=status.HTTP_200_OK)
        self._delete_auth_cookies(response)
        return response

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        result = self._get_and_blacklist_token(refresh_token)
        error_response = self._get_token_error_response(result)
        if error_response:
            return error_response
        return self._build_logout_response()
    
class TokenRefreshView(APIView):
    
    def _get_new_access_token(self, refresh_token):
        if not refresh_token:
            return None
        try:
            refresh = RefreshToken(refresh_token)
            return str(refresh.access_token)
        except TokenError:
            return False
    
    def _set_token_cookies(self, response, access_token, request):
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=True,
            samesite='None',
        )
        response.set_cookie(
            key='csrftoken',
            value=get_token(request),
            httponly=False,
            secure=True,
            samesite='None'
        )

    def _get_refresh_error_response(self, new_access_token):
        if new_access_token is None:
            return Response(
                {'detail': 'Refresh-Token fehlt.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if new_access_token is False:
            return Response(
                {'detail': 'Ungültiger Refresh-Token'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return None

    def _build_refresh_response(self, new_access_token, request):
        response = Response({
            'detail': 'Token refreshed',
            'access': new_access_token
        }, status=status.HTTP_200_OK)
        self._set_token_cookies(response, new_access_token, request)
        return response

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        new_access_token = self._get_new_access_token(refresh_token)
        error_response = self._get_refresh_error_response(new_access_token)
        if error_response:
            return error_response
        return self._build_refresh_response(new_access_token, request)
    
class PasswordResetView(APIView):
    
    def _send_reset_email_if_user_exists(self, email):
        try:
            user = User.objects.get(email=email, is_active=True)
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            send_password_reset_email(user, uidb64, token)
        except User.DoesNotExist:
            pass
    
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self._send_reset_email_if_user_exists(serializer.validated_data['email'])
        return Response(
            {'detail': 'An email has been sent to reset your password.'},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    
    def _decode_uid_and_get_user(self, uidb64):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            return User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return None
    
    def _validate_reset_token(self, user, token):
        return default_token_generator.check_token(user, token)
    
    def _update_password(self, user, new_password):
        user.set_password(new_password)
        user.save()

    def _get_validated_reset_user(self, uidb64, token):
        user = self._decode_uid_and_get_user(uidb64)
        if not user:
            return None, Response(
                {'error': 'Ungültiger Reset-Link.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not self._validate_reset_token(user, token):
            return None, Response(
                {'error': 'Der Reset-Link ist ungültig oder abgelaufen.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        return user, None

    def _reset_user_password(self, user, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self._update_password(user, serializer.validated_data['new_password'])

    def post(self, request, uidb64, token):
        user, error_response = self._get_validated_reset_user(uidb64, token)
        if error_response:
            return error_response
        self._reset_user_password(user, request)
        return Response(
            {'detail': 'Passwort wurde erfolgreich zurückgesetzt.'},
            status=status.HTTP_200_OK
        )