from rest_framework_simplejwt.authentication import JWTAuthentication

class CookieJWTAuthentication(JWTAuthentication):
    """
    JWT authentication that reads the access token from an HttpOnly cookie.
    Extends the default JWTAuthentication to read the access_token from
    an HttpOnly cookie instead of the Authorization header. This approach
    is more secure as it prevents token leakage via XSS attacks.
    """
    
    def authenticate(self, request):
        """
        Authenticate request by extracting and validating JWT from HttpOnly cookie.
        Retrieves the access_token from the request's cookies, validates it,
        and returns the authenticated user and validated token.
        Args:
            request (Request): The HTTP request object containing cookies.
        Returns:
            tuple: (user, validated_token) if authentication successful, None if no token found in cookies.
        Raises:
            InvalidToken: If token is invalid or expired.
            AuthenticationFailed: If user associated with token cannot be retrieved.
        """
        raw_token = request.COOKIES.get('access_token')
        if raw_token is None:
            return None
        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token