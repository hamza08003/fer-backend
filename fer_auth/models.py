from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import uuid


class UserProfile(models.Model):
    # User profile model that extends the default User model
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    name = models.CharField(max_length=100)
    email_verified = models.BooleanField(default=False)
    updated_at = models.DateTimeField(null=True, blank=True)
    
    # Email verification token fields
    email_verification_token = models.UUIDField(null=True, blank=True)
    email_token_created_at = models.DateTimeField(null=True, blank=True)
    email_token_expires_at = models.DateTimeField(null=True, blank=True)

    # Password reset token fields
    password_reset_token = models.UUIDField(null=True, blank=True)
    password_token_created_at = models.DateTimeField(null=True, blank=True)
    password_token_expires_at = models.DateTimeField(null=True, blank=True)
    password_token_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.name} ({self.user.username})"
    
    def create_email_verification_token(self):
        """
        Create a new email verification token
        """
        self.email_verification_token = uuid.uuid4()
        self.email_token_created_at = timezone.now()
        self.email_token_expires_at = timezone.now() + timedelta(hours=24)
        self.save()
        return self.email_verification_token
    
    def create_password_reset_token(self):
        """
        Create a new password reset token
        """
        self.password_reset_token = uuid.uuid4()
        self.password_token_created_at = timezone.now()
        self.password_token_expires_at = timezone.now() + timedelta(hours=1)
        self.password_token_used = False
        self.save()
        return self.password_reset_token
    
    def is_email_token_valid(self):
        """
        Check if email verification token is valid
        """
        if not self.email_verification_token:
            return False
        return timezone.now() <= self.email_token_expires_at
    
    def is_password_token_valid(self):
        """
        Check if password reset token is valid
        """
        if not self.password_reset_token or self.password_token_used:
            return False
        return timezone.now() <= self.password_token_expires_at
    
    def invalidate_email_token(self):
        """
        Invalidate email verification token
        """
        self.email_verification_token = None
        self.email_token_created_at = None
        self.email_token_expires_at = None
        self.save()
    
    def invalidate_password_token(self):
        """
        Invalidate password reset token
        """
        self.password_reset_token = None
        self.password_token_created_at = None
        self.password_token_expires_at = None
        self.password_token_used = False
        self.save()
    
    def use_password_token(self):
        """
        Mark password token as used
        """
        self.password_token_used = True
        self.save()
        