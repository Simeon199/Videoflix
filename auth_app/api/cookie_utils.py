from django.middleware.csrf import get_token


class CookieMixin:
    """
    Mixin providing reusable cookie operations for authentication views.
    Centralizes cookie setting, deletion, and authentication cookie management
    to avoid code duplication across LoginView, LogoutView, and TokenRefreshView.
    """

    def _set_cookie(self, response, key, value, httponly=True):
        """
        Set a secure cookie in the response.
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
        Set access token, refresh token, and CSRF token cookies.
        Args:
            response (Response): The response object to set cookies on.
            refresh (RefreshToken): JWT refresh token object.
            request (Request): HTTP request object used to generate CSRF token.
        """
        self._set_cookie(response, 'access_token', str(refresh.access_token))
        self._set_cookie(response, 'refresh_token', str(refresh))
        self._set_cookie(response, 'csrftoken', get_token(request), httponly=False)

    def _set_token_cookies(self, response, access_token, request):
        """
        Set new access token and CSRF token cookies (used for token refresh).
        Args:
            response (Response): The response object to set cookies on.
            access_token (str): The new access token.
            request (Request): HTTP request object used to generate CSRF token.
        """
        self._set_cookie(response, 'access_token', access_token)
        self._set_cookie(response, 'csrftoken', get_token(request), httponly=False)

    def _delete_auth_cookies(self, response):
        """
        Delete all authentication-related cookies from response.
        Args:
            response (Response): The response object to delete cookies from.
        """
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        response.delete_cookie('csrftoken')
