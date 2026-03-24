from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate


class RegistrationSerializer(serializers.Serializer):
    """
    Serializer for user registration.
    Validates and creates a new user account with email and password.
    Attributes:
        email (EmailField): User's email address, must be unique.
        password (CharField): User's password, write-only field.
        confirmed_password (CharField): Password confirmation, write-only field.
    """
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirmed_password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        """
        Validate that the email is unique.
        Args:
            value (str): The email address to validate.
        Returns:
            str: The validated email address.
        Raises:
            serializers.ValidationError: If a user with this email already exists.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Ein Benutzer mit dieser E-Mail existiert bereits.")
        return value
    
    def validate(self, data):
        """
        Validate that both password fields match.
        Args:
            data (dict): The serializer data containing password and confirmed_password.
        Returns:
            dict: The validated data.
        Raises:
            serializers.ValidationError: If password and confirmed_password don't match.
        """
        if data['password'] != data['confirmed_password']:
            raise serializers.ValidationError("Die Passwörter stimmen nicht überein.")
        return data
    
    def create(self, validated_data):
        """
        Create a new inactive user account.
        Args:
            validated_data (dict): Validated data containing email and password.
        Returns:
            User: The newly created user object with is_active set to False.
        """
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_active=False
        )
        return user

    
class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login authentication.
    Validates user credentials and authenticates the user.
    Attributes:
        email (EmailField): User's email address.
        password (CharField): User's password, write-only field.
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        """
        Authenticate user with email and password.
        Args:
            data (dict): The serializer data containing email and password.
        Returns:
            dict: The validated data with the authenticated user object.
        Raises:
            serializers.ValidationError: If credentials are invalid or account is inactive.
        """
        user = authenticate(username=data['email'], password=data['password'])
        if user is None:
            raise serializers.ValidationError("Ungültige Anmeldedaten.")
        if not user.is_active:
            raise serializers.ValidationError("Dieses Konto is noch nicht aktiviert.")
        data['user'] = user
        return data

    
class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for initiating password reset.
    Validates that the provided email address exists in the system.
    Attributes:
        email (EmailField): User's email address.
    """
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Validate that the email belongs to an active user.
        Args:
            value (str): The email address to validate.
        Returns:
            str: The validated email address.
        """
        if not User.objects.filter(email=value, is_active=True).exists():
            pass
        return value  

    
class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming password reset with new password.
    Validates that both password fields match before updating the password.
    Attributes:
        new_password (CharField): The new password, write-only field.
        confirm_password (CharField): Password confirmation, write-only field.
    """
    
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        """
        Validate that both password fields match.
        Args:
            data (dict): The serializer data containing new_password and confirm_password.
        Returns:
            dict: The validated data.
        Raises:
            serializers.ValidationError: If passwords don't match.
        """
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Die Passwörter stimmen nicht überein.")
        return data