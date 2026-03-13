import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from auth_app.api.serializers import LoginSerializer

LOGIN_URL = "/api/login/"
LOGOUT_URL = "/api/logout/"
TOKEN_REFRESH_URL = "/api/token/refresh"

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def active_user(create_user):
    return create_user(
        email="active@example.com", 
        password="securePass123!",
        is_active=True
    )

@pytest.fixture
def inactive_user(create_user):
    return create_user(
        email="inactive@example.com",
        password="securePass123!",
        is_active=False
    )

# LoginSerializer

@pytest.mark.django_db
class TestLoginSerializer:

    def test_valid_credentials(self, active_user):
        data = {
            "email": "active@example.com",
            "password": "securePass123!"
        }
        serializer = LoginSerializer(data=data)
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data["user"] == active_user

    def test_wrong_password(self, active_user):
        data = {
            "email": "active@example.com",
            "password": "wrongPassword"
        }
        serializer = LoginSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors

    def test_nonexistent_user(self):
        data = {
            "email": "ghost@example.com",
            "password": "somePass123!"
        }
        serializer=LoginSerializer(data=data)
        assert not serializer.is_valid()

    def test_inactive_user_rejected(self, inactive_user):
        data = {
            "email": "inactive@example.com",
            "password": "securePass123!"
        }
        serializer = LoginSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors


    def test_missing_email(self):
        serializer = LoginSerializer(data={
            "password": "securePass123!"
        })
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_missing_password(self):
        serializer = LoginSerializer(data={
            "email": "active@example.com"
        })
        assert not serializer.is_valid()
        assert "password" in serializer.errors

# LoginView

@pytest.mark.django_db
class TestLoginView:
    def test_successfull_login_status(self, api_client, active_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.status_code == 200

    def test_successfull_login_response_body(self, api_client, active_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.data["detail"] == "Login successful"
        assert response.data["user"]["id"] == active_user.id
        assert response.data["user"]["username"] == active_user.username

    def test_access_cookie_set(self, api_client, active_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert "access_token" in response.cookies

    def test_refresh_token_cookie_set(self, api_client, active_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert "refresh_token" in response.cookies

    def test_cookies_are_httponly(self, api_client, active_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.cookies["access_token"]["httponly"]
        assert response.cookies["refresh_token"]["httponly"]

    def test_wrong_credentials_rejected(self, api_client, active_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "wrongPass!"
            },
            format="json"
        )
        assert response.status_code == 400

    def test_inactive_user_rejected(self, api_client, inactive_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "inactive@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.status_code == 400

    def test_missing_fields_rejected(self, api_client):
        response = api_client.post(LOGOUT_URL, {}, format="json")
        assert response.status_code == 400

    def test_no_tokens_in_response_body(self, api_client, active_user):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert "access_token" not in response.data
        assert "refresh_token" not in response.data

# LogoutView

@pytest.mark.django_db
class TestLogoutView:
    def _login(self, api_client, email, password):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": email,
                "password": password
            },
            format="json"
        )
        return response.cookies.get("refresh_token").value
    
    def test_successful_logout_status(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] == refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 200

    def test_successful_response_body(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] == refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert "Logout successful" in response.data["detail"]
        assert "Refresh token is now invalid" in response.data["detail"]

    def test_cookies_deleted_after_logout(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.cookies["access_token"].value == ""
        assert response.cookies["refresh_token"].value == ""

    def test_logout_without_cookie_returns_400(self, api_client, active_user):
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 400
        assert "Refresh-Token fehlt" in response.data["detail"]

    def test_logout_with_invalid_token_returns_400(self, api_client):
        api_client.cookies["refresh_token"] = "this.is.not.a.valid.token"
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 400

    def test_token_blacklisted_after_logout(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token

        # Erster Logout - erfolgreich
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 200

        # Zweiter Logout mit demselben Token - muss fehlschlagen
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 400

# TokenRefreshView

@pytest.mark.django_db
class TokenRefreshView:
    def _login(self, api_client, email, password):
        response = api_client.post(
            LOGIN_URL,
            {
                "email": email,
                "password": password
            },
            format="json"
        )
        return response.cookies.get("refresh_token").value
    
    def test_successfull_refresh_status(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.status_code == 200

    def test_successful_refresh_response_body(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.data["detail"] == "Token refreshed"
        assert "access" in response.data

    def test_new_access_cookie_is_set(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert "access_token" in response.cookies
        assert response.cookies["access_token"].value != ""

    def test_new_access_cookie_is_httponly(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.cookies["access_token"]["httponly"]

    def test_refresh_without_cookie_returns_400(self, api_client):
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.status_code == 400
        assert "Refresh-Token fehlt" in response.data["detail"]

    def test_refresh_with_invalid_token_returns_401(self, api_client):
        api_client.cookies["refresh_token"] = "this.is.not.a.valid.token"
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.status_code == 401
        assert "Ungültiger Refresh-Token" in response.data["detail"]

    def test_no_token_leakage_in_body(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert "access_token" not in response.data

    def test_refresh_token_cookie_not_modified(self, api_client, active_user):
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert "refresh_token" not in response.cookies