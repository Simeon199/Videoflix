from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError


def blacklist_refresh_token(refresh_token):
    """
    Blacklist a refresh token to invalidate it.
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


def generate_access_token(refresh_token):
    """
    Generate a new access token from a refresh token.
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


def get_token_error_response(result, missing_msg, invalid_msg, invalid_status=status.HTTP_400_BAD_REQUEST):
    """
    Build error response based on a token operation result.
    Args:
        result: The result of a token operation (None=missing, False=invalid, other=success).
        missing_msg (str): Error message when token is missing.
        invalid_msg (str): Error message when token is invalid.
        invalid_status: HTTP status for invalid token. Defaults to 400.
    Returns:
        Response: HTTP error response if there was an issue, None if successful.
    """
    if result is None:
        return Response(
            {'detail': missing_msg},
            status=status.HTTP_400_BAD_REQUEST
        )
    if result is False:
        return Response(
            {'detail': invalid_msg},
            status=invalid_status
        )
    return None
