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
    """
    API view for user registration.
    Handles POST requests to register new users with email and password.
    Creates inactive user accounts and sends activation emails.
    """
    
    def _build_user_response(self, user, token):
        """
        Build success response with user data and token.
        Args:
            user (User): The created user object.
            token (str): The activation token for the user.
        Returns:
            Response: HTTP 201 response with user data and token.
        """
        return Response({
            'user': {'id': user.id, 'email': user.email},
            'token': token
        }, status=status.HTTP_201_CREATED)

    def post(self, request):
        """
        Handle user registration POST request.
        Validates registration data, creates a new user account,
        generates an activation token, and sends activation email.
        Args:
            request (Request): HTTP request containing email and password.
        Returns:
            Response: HTTP 201 with user data if successful, HTTP 400 if validation fails.
        """
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        send_activation_email(user, uidb64, token)
        return self._build_user_response(user, token)
    
class ActivationView(APIView):
    """
    API view for user account activation.
    Handles GET requests to activate user accounts using tokens.
    Validates the activation token and sets user account as active.
    """
    
    def _decode_uid_and_get_user(self, uidb64):
        """
        Decode the base64-encoded user ID and retrieve the user object.
        Args:
            uidb64 (str): Base64-encoded user ID.
        Returns:
            User: The user object if found and valid, None otherwise.
        """
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            return User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return None
    
    def _validate_user_for_activation(self, user):
        """
        Validate that user exists and is not already active.
        Args:
            user (User): The user object to validate.
        Returns:
            bool: True if user is valid for activation, False otherwise.
        """
        if user and user.is_active:
            return False
        return user is not None
    
    def _activate_user(self, user, token):
        """
        Activate user account if token is valid.
        Args:
            user (User): The user object to activate.
            token (str): The activation token to validate.
        Returns:
            bool: True if activation successful, False if token is invalid.
        """
        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return True
        return False
    
    def _get_validated_user(self, uidb64):
        """
        Get and validate user for activation.
        Args:
            uidb64 (str): Base64-encoded user ID.
        Returns:
            User: The validated user object if valid for activation, None otherwise.
        """
        user = self._decode_uid_and_get_user(uidb64)
        if not user or not self._validate_user_for_activation(user):
            return None
        return user

    def _activation_error(self):
        """
        Build error response for failed activation.
        Returns:
            Response: HTTP 400 response with error message.
        """
        return Response(
            {'error': 'Aktivierung fehlgeschlagen.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    def get(self, request, uidb64, token):
        """
        Handle user account activation GET request.
        Validates the activation token and activates the user account if valid.
        Args:
            request (Request): HTTP request.
            uidb64 (str): Base64-encoded user ID from URL.
            token (str): Activation token from URL.
        Returns:
            Response: HTTP 200 if successful, HTTP 400 if activation fails.
        """
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
    """
    API view for user login.
    Handles POST requests to authenticate users and generate JWT tokens.
    Sets authentication cookies for access token, refresh token, and CSRF token.
    """
    
    def _set_cookie(self, response, key, value, httponly=True):
        """
        Set a cookie in the response.
        Args:
            response (Response): The response object to set cookie on.
            key (str): Cookie name.
            value (str): Cookie value.
            httponly (bool): Whether cookie is HTTP-only. Defaults to True.
        """
        response.set_cookie(
            key=key,
            value=value,
            httponly=httponly,
            secure=True,
            samesite='None',
        )
    
    def _set_authentication_cookies(self, response, refresh, request):
        """
        Set authentication-related cookies (access token, refresh token, CSRF token).
        Args:
            response (Response): The response object to set cookies on.
            refresh (RefreshToken): JWT refresh token object.
            request (Request): HTTP request object used to generate CSRF token.
        """
        self._set_cookie(response, 'access_token', str(refresh.access_token))
        self._set_cookie(response, 'refresh_token', str(refresh))
        self._set_cookie(response, 'csrftoken', get_token(request), httponly=False)

    def _build_login_response(self, user, refresh, request):
        """
        Build successful login response with user data and authentication cookies.
        Args:
            user (User): The authenticated user object.
            refresh (RefreshToken): JWT refresh token object.
            request (Request): HTTP request object.
        Returns:
            Response: HTTP 200 response with user data and authentication cookies.
        """
        response = Response({
            'detail': 'Login successful',
            'user': {'id': user.id, 'username': user.username}
        }, status=status.HTTP_200_OK)
        self._set_authentication_cookies(response, refresh, request)
        return response

    def post(self, request):
        """
        Handle user login POST request.
        Validates credentials, authenticates user, generates JWT tokens,
        and sets authentication cookies.
        Args:
            request (Request): HTTP request containing email and password.
        Returns:
            Response: HTTP 200 with user data if successful, HTTP 400 if validation fails.
        """
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        return self._build_login_response(user, refresh, request)

class LogoutView(APIView):
    """
    API view for user logout.
    Handles POST requests to logout users by blacklisting refresh tokens
    and deleting authentication cookies.
    """
    
    def _get_and_blacklist_token(self, refresh_token):
        """
        Get refresh token from cookie and add it to blacklist.
        Args:
            refresh_token (str): The refresh token string from cookies.
        Returns:
            bool: True if successfully blacklisted, False if invalid, None if missing.
        """
        if not refresh_token:
            return None
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return True
        except TokenError:
            return False
    
    def _delete_auth_cookies(self, response):
        """
        Delete all authentication-related cookies from response.
        Args:
            response (Response): The response object to delete cookies from.
        """
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        response.delete_cookie('csrftoken')

    def _get_token_error_response(self, result):
        """
        Build error response based on token blacklist result.
        Args:
            result (bool/None): Result from _get_and_blacklist_token method.
        Returns:
            Response: HTTP error response if there was an issue, None if successful.
        """
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
        """
        Build successful logout response with deleted cookies.
        Returns:
            Response: HTTP 200 response with logout message and deleted cookies.
        """
        response = Response({
            'detail': 'Logout successful! All tokens will be deleted. Refresh token is now invalid.'
        }, status=status.HTTP_200_OK)
        self._delete_auth_cookies(response)
        return response

    def post(self, request):
        """
        Handle user logout POST request.
        Blacklists the refresh token and deletes authentication cookies.
        Args:
            request (Request): HTTP request containing refresh_token cookie.
        Returns:
            Response: HTTP 200 if successful, HTTP 400 if token missing/invalid.
        """
        refresh_token = request.COOKIES.get('refresh_token')
        result = self._get_and_blacklist_token(refresh_token)
        error_response = self._get_token_error_response(result)
        if error_response:
            return error_response
        return self._build_logout_response()
    
class TokenRefreshView(APIView):
    """
    API view for refreshing JWT tokens.
    Handles POST requests to refresh expired access tokens using refresh tokens.
    Sets new access and CSRF tokens in cookies.
    """
    
    def _get_new_access_token(self, refresh_token):
        """
        Generate new access token from refresh token.
        Args:
            refresh_token (str): The refresh token string from cookies.
        Returns:
            str: New access token if successful, False if invalid, None if missing.
        """
        if not refresh_token:
            return None
        try:
            refresh = RefreshToken(refresh_token)
            return str(refresh.access_token)
        except TokenError:
            return False
    
    def _set_token_cookies(self, response, access_token, request):
        """
        Set new access token and CSRF token cookies in response.
        Args:
            response (Response): The response object to set cookies on.
            access_token (str): The new access token.
            request (Request): HTTP request object used to generate CSRF token.
        """
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
        """
        Build error response based on token refresh result.
        Args:
            new_access_token (str/bool/None): Result from _get_new_access_token.
        Returns:
            Response: HTTP error response if there was an issue, None if successful.
        """
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
        """
        Build successful token refresh response with new access token and cookies.
        Args:
            new_access_token (str): The new access token.
            request (Request): HTTP request object.
        Returns:
            Response: HTTP 200 response with new access token and cookies.
        """
        response = Response({
            'detail': 'Token refreshed',
            'access': new_access_token
        }, status=status.HTTP_200_OK)
        self._set_token_cookies(response, new_access_token, request)
        return response

    def post(self, request):
        """
        Handle token refresh POST request.
        Validates refresh token and generates new access token.
        Args:
            request (Request): HTTP request containing refresh_token cookie.
        Returns:
            Response: HTTP 200 with new access token if successful, HTTP 400/401 if invalid.
        """
        refresh_token = request.COOKIES.get('refresh_token')
        new_access_token = self._get_new_access_token(refresh_token)
        error_response = self._get_refresh_error_response(new_access_token)
        if error_response:
            return error_response
        return self._build_refresh_response(new_access_token, request)
    
class PasswordResetView(APIView):
    """
    API view for initiating password reset.
    Handles POST requests to send password reset emails.
    Only sends email if the email belongs to an active user (security measure).
    """
    
    def _send_reset_email_if_user_exists(self, email):
        """
        Send password reset email if active user with given email exists.
        Args:
            email (str): The email address to send reset link to.
        """
        try:
            user = User.objects.get(email=email, is_active=True)
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            send_password_reset_email(user, uidb64, token)
        except User.DoesNotExist:
            pass
    
    def post(self, request):
        """
        Handle password reset POST request.
        Validates email, generates reset token, and sends password reset email.
        Returns success message regardless of whether email exists (for security).
        Args:
            request (Request): HTTP request containing email address.
        Returns:
            Response: HTTP 200 with success message (always returns success for security).
        """
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self._send_reset_email_if_user_exists(serializer.validated_data['email'])
        return Response(
            {'detail': 'An email has been sent to reset your password.'},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    """
    API view for confirming password reset with new password.
    Handles POST requests to validate reset token and update user password.
    Validates token and ensures new passwords match before updating.
    """
    
    def _decode_uid_and_get_user(self, uidb64):
        """
        Decode the base64-encoded user ID and retrieve the user object.
        Args:
            uidb64 (str): Base64-encoded user ID.
        Returns:
            User: The user object if found and valid, None otherwise.
        """
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            return User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return None
    
    def _validate_reset_token(self, user, token):
        """
        Validate reset token for given user.
        Args:
            user (User): The user object.
            token (str): The reset token to validate.
        Returns:
            bool: True if token is valid, False otherwise.
        """
        return default_token_generator.check_token(user, token)
    
    def _update_password(self, user, new_password):
        """
        Update user password and save to database.
        Args:
            user (User): The user object to update.
            new_password (str): The new password.
        """
        user.set_password(new_password)
        user.save()

    def _get_validated_reset_user(self, uidb64, token):
        """
        Get and validate user for password reset.
        Args:
            uidb64 (str): Base64-encoded user ID.
            token (str): The reset token.
        Returns:
            tuple: (user, error_response) - User if valid, error Response otherwise.
        """
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
        """
        Validate and update user password from request data.
        Args:
            user (User): The user object to update.
            request (Request): HTTP request containing new password data.
        """
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self._update_password(user, serializer.validated_data['new_password'])

    def post(self, request, uidb64, token):
        """
        Handle password reset confirmation POST request.
        Validates reset token and updates user password if token is valid.
        Args:
            request (Request): HTTP request containing new password and confirmation.
            uidb64 (str): Base64-encoded user ID from URL.
            token (str): Reset token from URL.
        Returns:
            Response: HTTP 200 if successful, HTTP 400 if validation fails.
        """
        user, error_response = self._get_validated_reset_user(uidb64, token)
        if error_response:
            return error_response
        self._reset_user_password(user, request)
        return Response(
            {'detail': 'Passwort wurde erfolgreich zurückgesetzt.'},
            status=status.HTTP_200_OK
        )