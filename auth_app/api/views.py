from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegistrationSerializer, LoginSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
from .utils import send_activation_email, send_password_reset_email, decode_uid_and_get_user
from .cookie_utils import CookieMixin
from .token_utils import blacklist_refresh_token, generate_access_token, get_token_error_response

class HtmlRequestMixin:
    def _wants_html(self, request):
        """
        Check if the client accepts HTML responses.
        Examines the HTTP Accept header to determine if HTML is acceptable.
        Args:
            request (Request): HTTP request object.
        Returns:
            bool: True if 'text/html' is in Accept header, False otherwise.
        """
        accept = request.META.get('HTTP_ACCEPT', '')
        return 'text/html' in accept

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
        user = decode_uid_and_get_user(uidb64)
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
        Handle account activation GET request.
        Validates the user and activation token, activates the account on success.
        Called by the frontend activation page via JS fetch.
        Args:
            request (Request): HTTP request object.
            uidb64 (str): Base64-encoded user ID from the activation link.
            token (str): Activation token from the activation link.
        Returns:
            Response: HTTP 200 with success message on successful activation,
            or HTTP 400 if the user is invalid or the token check fails.
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


class LoginView(CookieMixin, APIView):
    """
    API view for user login.
    Handles POST requests to authenticate users and generate JWT tokens.
    Sets authentication cookies for access token, refresh token, and CSRF token.
    """

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


class LogoutView(CookieMixin, APIView):
    """
    API view for user logout.
    Handles POST requests to logout users by blacklisting refresh tokens
    and deleting authentication cookies.
    """

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
        result = blacklist_refresh_token(refresh_token)
        error = get_token_error_response(
            result, 'Refresh-Token fehlt.', 'Token ist ungültig oder bereits abgelaufen.'
        )
        if error:
            return error
        return self._build_logout_response()


class TokenRefreshView(CookieMixin, APIView):
    """
    API view for refreshing JWT tokens.
    Handles POST requests to refresh expired access tokens using refresh tokens.
    Sets new access and CSRF tokens in cookies.
    """

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
        new_access_token = generate_access_token(refresh_token)
        error = get_token_error_response(
            new_access_token, 'Refresh-Token fehlt.', 'Ungültiger Refresh-Token',
            invalid_status=status.HTTP_401_UNAUTHORIZED
        )
        if error:
            return error
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


class PasswordResetConfirmView(HtmlRequestMixin, APIView):
    """
    API view for confirming password reset with new password.
    Handles POST requests to validate reset token and update user password.
    Validates token and ensures new passwords match before updating.
    """

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
        user = decode_uid_and_get_user(uidb64)
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

    def get(self, request, uidb64, token):
        """
        Handle password reset GET request.
        Validates the user and reset token before redirecting HTML clients to the
        frontend password reset page.
        Args:
            request (Request): HTTP request object.
            uidb64 (str): Base64-encoded user ID from the reset link.
            token (str): Reset token from the reset link.
        Returns:
            Response: Redirect to frontend reset page (with uid and token as query
            params) if HTML client and token is valid, HTTP 200 with confirmation
            message for API clients, or HTTP 400 if the user is invalid or the
            token is expired.
        """
        user, error_response = self._get_validated_reset_user(uidb64, token)
        if error_response:
            return error_response
        if self._wants_html(request):
            return redirect(
                f"{settings.FRONTEND_DOMAIN}{settings.FRONTEND_RESET_PASSWORD_PATH}?uid={uidb64}&token={token}"
            )
        return Response(
            {'detail': 'Token is valid. Use POST to reset your password.'},
            status=status.HTTP_200_OK
        )

    def post(self, request, uidb64, token):
        """
        Handle password reset confirmation POST request.
        Validates the reset token and updates the user password if the token is
        valid. 
            request (Request): HTTP request containing the new password and its
            confirmation.
            uidb64 (str): Base64-encoded user ID from the URL.
            token (str): Reset token from the URL.
        Returns:
            Response: HTTP 200 with success message if the password was updated,
            or HTTP 400 if the user is invalid, the token is expired, or the
            password validation fails.
        """
        user, error_response = self._get_validated_reset_user(uidb64, token)
        if error_response:
            return error_response
        self._reset_user_password(user, request)
        return Response(
            {'detail': 'Passwort wurde erfolgreich zurückgesetzt.'},
            status=status.HTTP_200_OK
        )