from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import UserProfile
import re


class UserRegistrationSerializer(serializers.ModelSerializer):
    name = serializers.CharField(max_length=100)
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'name', 'password', 'password_confirm']
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value
    
    def validate_username(self, value):
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError("Username can only contain letters, numbers, and underscores")    
        return value
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        
        return attrs
    
    def create(self, validated_data):
        name = validated_data.pop('name')
        validated_data.pop('password_confirm')
        
        user = User.objects.create_user(**validated_data)
        UserProfile.objects.create(user=user, name=name)
        
        return user


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    last_login = serializers.DateTimeField(source='user.last_login', read_only=True)
    date_joined = serializers.DateTimeField(source='user.date_joined', read_only=True)
    updated_at = serializers.SerializerMethodField()
    
    class Meta:
        model = UserProfile
        fields = ['name', 'username', 'email', 'email_verified', 'date_joined', 'last_login', 'updated_at']
    
    def get_updated_at(self, obj):
        obj.refresh_from_db()
        if obj.updated_at is None:
            return "Not Updated Yet"
        return obj.updated_at


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.UUIDField()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetSerializer(serializers.Serializer):
    token = serializers.UUIDField()
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        
        return attrs
