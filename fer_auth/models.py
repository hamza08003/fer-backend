from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import uuid
import pyotp


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

    # 2FA fields
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=255, null=True, blank=True)
    two_factor_backup_codes = models.JSONField(default=list, blank=True, null=True)
    two_factor_temp_secret = models.CharField(max_length=255, null=True, blank=True)
    
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

    def generate_2fa_secret(self):
        """
        Generate a new temporary 2FA secret for setup
        """
        secret = pyotp.random_base32()
        self.two_factor_temp_secret = secret
        self.save()
        return secret

    def activate_2fa(self, code):
        """
        Activate 2FA after verification with a valid code
        """
        if not self.two_factor_temp_secret:
            return False
            
        totp = pyotp.TOTP(self.two_factor_temp_secret)
        if totp.verify(code):
            self.two_factor_secret = self.two_factor_temp_secret
            self.two_factor_temp_secret = None
            self.two_factor_enabled = True
            self.generate_backup_codes()
            self.updated_at = timezone.now()
            self.save()
            return True
        return False
    
    def verify_2fa_code(self, code):
        """
        Verify a 2FA code or backup code
        """

        # skip if 2FA is disabled - meaning that if 2FA is not enabled or no secret is set
        # then let the user log in without 2FA
        if not self.two_factor_enabled or not self.two_factor_secret:
            return True
            
        # check if it's a regular TOTP code
        totp = pyotp.TOTP(self.two_factor_secret)
        if totp.verify(code):
            return True
            
        # check if it's a backup code
        if self.two_factor_backup_codes and code in self.two_factor_backup_codes:
            # remove the used backup code
            self.two_factor_backup_codes.remove(code)
            self.save()
            return True
            
        return False
    
    def disable_2fa(self):
        """
        Disable 2FA for the user
        """
        self.two_factor_enabled = False
        self.two_factor_secret = None
        self.two_factor_temp_secret = None
        self.two_factor_backup_codes = []
        self.updated_at = timezone.now()
        self.save()
        
    def generate_backup_codes(self, count=8):
        """
        Generate backup codes for 2FA recovery
        """
        backup_codes = []
        for _ in range(count):
            # generate a random 8-character backup code
            code = ''.join([str(uuid.uuid4().int)[:8] for _ in range(1)])
            backup_codes.append(code)
            
        self.two_factor_backup_codes = backup_codes
        self.save()
        return backup_codes
        
    def get_totp_uri(self):
        """
        Get the OTP Auth URI for QR code generation
        """
        if not self.two_factor_temp_secret and not self.two_factor_secret:
            return None
            
        secret = self.two_factor_temp_secret or self.two_factor_secret
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=self.user.email,
            issuer_name="FER App"
        )
        