from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .serializers import RegistrationSerializer, LoginSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
from .utils import send_activation_email, send_password_reset_email

class RegistrationView(APIView):
    
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        send_activation_email(user, uidb64, token)

        return Response({
            'user': {
                'id': user.id,
                'email': user.email
            },
            'token': token
        }, status=status.HTTP_201_CREATED)
    
class ActivationView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {'error': 'Aktivierung fehlgeschlagen'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response(
                {'message': 'Account successfully activated.'},
                status=status.HTTP_200_OK
            )
        
        return Response(
            {'error': 'Aktivierung fehlgeschlagen.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
class LoginView(APIView):

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        refresh = RefreshToken.for_user(user)

        response = Response({
            'detail': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username
            }
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            secure=True,
            samesite='None',
        )

        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            secure=True,
            samesite='None'
        )

        return response

class LogoutView(APIView):

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response(
                {'detail': 'Refresh-Token fehlt.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response(
                {'detail': 'Token ist ungültig oder bereits abgelaufen.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        response = Response({
            'detail': 'Logout successful! All tokens will be deleted. Refresh token is now invalid.'
        }, status=status.HTTP_200_OK)

        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')

        return response
    
class TokenRefreshView(APIView):

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response(
                {
                    'detail': 'Refresh-Token fehlt.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
        except TokenError:
            return Response(
                {
                    'detail': 'Ungültiger Refresh-Token'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        response = Response({
            'detail': 'Token refreshed',
            'access': new_access_token
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key='access_token',
            value=new_access_token,
            httponly=True,
            secure=True,
            samesite='None',
        )

        return response
    
class PasswordResetView(APIView):
    
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email, is_active=True)
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            send_password_reset_email(user, uidb64, token)
        except User.DoesNotExist:
            pass # Keine Informationen nach außen geben

        return Response(
            {'detail': 'An email has been sent to reset your password.'},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {'error': 'Ungültiger Reset-Link.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not default_token_generator.check_token(user, token):
            return Response(
                {'error': 'Der Reset-Link ist ungültig oder abgelaufen.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user.set_password(serializer.validated_data['new_password'])
        user.save()

        return Response(
            {'detail': 'Passwort wurde erfolgreich zurückgesetzt.'},
            status=status.HTTP_200_OK
        )