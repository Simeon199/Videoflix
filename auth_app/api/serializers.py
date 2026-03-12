from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirmed_password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Ein Benutzer mit dieser E-Mail existiert bereits.")
        return value
    
    def validate(self, data):
        if data['password'] != data['confirmed_password']:
            raise serializers.ValidationError("Die Passwörter stimmen nicht überein.")
        return data
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_active=False
        )
        return user
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data['email'], password=data['password'])
        if user is None:
            raise serializers.ValidationError("Ungültige Anmeldedaten.")
        if not user.is_active:
            raise serializers.ValidationError("Dieses Konto is noch nicht aktiviert.")
        data['user'] = user
        return data
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value, is_active=True).exists():
            # Aus Sicherheitsgründen keinen Hinweis geben, ob die Email existiert (HTTP 200 immer).
            pass
        return value  
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Die Passwörter stimmen nicht überein.")
        return data