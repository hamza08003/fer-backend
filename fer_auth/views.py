import logging
import re

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.db import transaction

from drf_spectacular.utils import extend_schema
from .docs.auth_endpoints_docs import *

from .models import UserProfile
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    ChangePasswordSerializer,
    EmailVerificationSerializer,
    PasswordResetRequestSerializer,
    PasswordResetSerializer,
    TwoFactorSetupSerializer,
    TwoFactorVerifySerializer,
    TwoFactorDisableSerializer,
)
from .utils import (send_verification_email, send_password_reset_email, 
                   generate_qr_code_base64, send_2fa_enabled_email, send_2fa_disabled_email)


# Configure logging
logger = logging.getLogger(__name__)


#################################################
#           AUTHENTICATION ENDPOINTS
#################################################

@extend_schema(**registration_schema)
@api_view(['POST'])
@permission_classes([AllowAny])
def register(req):
    """
    Register a new user account.

    This endpoint creates a new user with the provided credentials and sends
    a verification email to the user's email address. The registration process
    includes validation for:

    - Unique username
    - Valid email format
    - Password strength
    - Matching password confirmation

    The user's email verification status is initially set to False until they
    verify their email using the verification link sent.

    Args:
        req (Request): Django REST Framework request object containing:
            - username (str)
            - email (str)
            - name (str)
            - password (str)
            - password_confirm (str)

    Returns:
        Response: JSON response containing:
            - success (bool): Whether the registration was successful
            - message (str): Descriptive status message
            - user (dict, optional): User details (on success)
            - errors (dict, optional): Validation errors (on failure)

    Raises:
        400 Bad Request: If the provided data is invalid
        500 Internal Server Error: If user creation fails unexpectedly
    """

    serializer = UserRegistrationSerializer(data=req.data)
    
    if serializer.is_valid():
        try:
            user = serializer.save()
            
            # send a verification email
            send_verification_email(user)
            
            return Response({
                'success': True,
                'message': 'Account created successfully. Please check your email to verify your account.',
                'user': {
                    'username': user.username,
                    'email': user.email,
                    'name': user.profile.name
                }
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return Response({
                'success': False,
                'message': 'Registration failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({
        'success': False,
        'message': 'Invalid data provided.',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(**login_schema)
@api_view(['POST'])
@permission_classes([AllowAny])
def login(req):
    """
    Authenticate a user and return an authentication token.

    This endpoint verifies the provided username and password. If the user is 
    active and their email is verified, an authentication token is returned 
    for future API access. The user's `last_login` timestamp is also updated 
    on successful login.

    If 2FA is enabled for the user, a temporary token is provided that must be
    used with a valid 2FA code to complete the login process.

    Login is denied if:
    - The user has not verified their email
    - The account is deactivated
    - Credentials are incorrect

    Args:
        req (Request): Django REST Framework request object containing:
            - username (str)
            - password (str)

    Returns:
        Response: JSON response containing:
            - success (bool): Whether authentication was successful
            - message (str): Descriptive status message
            - token (str, optional): Authentication token (on success)
            - temp_token (str, optional): Temporary token for 2FA verification
            - two_factor_required (bool): Whether 2FA verification is required
            - user (dict, optional): Basic user details (on success)
            - errors (dict, optional): Validation errors (on failure)
            - email_verified (bool, optional): If login fails due to unverified email

    Status Codes:
        200 OK: Login successful or 2FA required
        400 Bad Request: Invalid credentials, unverified email, or deactivated account
    """

    serializer = UserLoginSerializer(data=req.data)
    
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # authenticate user
        user = authenticate(username=username, password=password)
        
        if user:
            if user.is_active:
                # check if email is verified
                if not user.profile.email_verified:
                    return Response({
                        'success': False,
                        'message': 'Please verify your email address before logging in.',
                        'email_verified': False
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Check if 2FA is enabled
                if user.profile.two_factor_enabled:
                    # create a temporary token for 2FA verification
                    temp_token, _ = Token.objects.get_or_create(user=user)
                    
                    return Response({
                        'success': True,
                        'message': 'Please enter your 2FA verification code.',
                        'two_factor_required': True,
                        'temp_token': temp_token.key,
                        'user': {
                            'username': user.username,
                            'name': user.profile.name,
                        }
                    }, status=status.HTTP_200_OK)
                
                # update last login time
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                
                # create or get token for non-2FA users
                token, _ = Token.objects.get_or_create(user=user)
                
                return Response({
                    'success': True,
                    'message': 'Login successful.',
                    'token': token.key,
                    'two_factor_required': False,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'name': user.profile.name,
                        'email_verified': user.profile.email_verified,
                        'two_factor_enabled': user.profile.two_factor_enabled
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'message': 'Account is deactivated.'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'success': False,
                'message': 'Invalid username or password.'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({
        'success': False,
        'message': 'Invalid data provided.',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(**logout_schema)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(req):
    """
    Log out the current user.

    Deletes the user's authentication token from the database, effectively
    ending their session. Future requests using the token will be rejected.

    Authentication is required via token in the request header.

    Args:
        req (Request): DRF request object containing an authenticated user.

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)

    Status Codes:
        200 OK: Logout successful.
        400 Bad Request: User not logged in or token not found.
    """

    try:
        # delete user token
        token = Token.objects.get(user=req.user)
        token.delete()
        
        return Response({
            'success': True,
            'message': 'Logged out successfully.'
        }, status=status.HTTP_200_OK)
        
    except Token.DoesNotExist:
        return Response({
            'success': False,
            'message': 'User not logged in.'
        }, status=status.HTTP_400_BAD_REQUEST)


#################################################
#          EMAIL VERIFICATION ENDPOINTS
#################################################

@extend_schema(**verify_email_schema)
@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(req, token):
    """
    Verify a user's email address.

    Marks the user's email as verified if the token is valid and unexpired.
    Deletes the token after successful verification.

    This endpoint is typically accessed via a link in the verification email.

    Args:
        req (Request): DRF request object.
        token (UUID): Verification token from email.

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)

    Status Codes:
        200 OK: Email verified successfully.
        400 Bad Request: Token is invalid or expired.
        404 Not Found: Token does not exist.
    """

    try:
        # find user profile with matching token
        profile = UserProfile.objects.get(email_verification_token=token)
        
        if not profile.is_email_token_valid():
            return Response({
                'success': False,
                'message': 'Verification link has expired.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # mark email as verified and invalidate token
        profile.email_verified = True
        profile.invalidate_email_token()
        
        return Response({
            'success': True,
            'message': 'Email verified successfully. You can now login.'
        }, status=status.HTTP_200_OK)
        
    except UserProfile.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Invalid verification token.'
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(**resend_verification_schema)
@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification(req):
    """
    Resend a verification email to the user.

    Sends a new verification email if the account exists and the email is
    not already verified. Previous tokens are invalidated.

    For security, this endpoint does not reveal whether the email exists.

    Args:
        req (Request): DRF request object with:
            - email (str)

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)

    Status Codes:
        200 OK: Verification email sent.
        400 Bad Request: Email already verified, missing, or invalid.
    """

    email = req.data.get('email').strip().lower()

    if not email:
        return Response({
            'success': False,
            'message': 'Email is required.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        
        if user.profile.email_verified:
            return Response({
                'success': False,
                'message': 'Email is already verified.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # send new verification email
        send_verification_email(user)
        
        return Response({
            'success': True,
            'message': 'Verification email sent successfully.'
        }, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response({
            'success': False,
            'message': 'User with this email does not exist.'
        }, status=status.HTTP_400_BAD_REQUEST)


#################################################
#       PROFILE MANAGEMENT ENDPOINTS
#################################################

@extend_schema(**profile_schema)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile(req):
    """
    Retrieve the current user's profile.

    Returns the authenticated user's profile details including username,
    email, name, and account status information.

    Authentication is required via token in the request header.

    Args:
        req (Request): DRF request object with authenticated user.

    Returns:
        Response: JSON response with:
            - success (bool)
            - profile (dict)
            - message (str, optional)

    Status Codes:
        200 OK: Profile retrieved successfully.
        404 Not Found: Profile not found for user.
    """

    try:
        user = User.objects.get(pk=req.user.pk)
        profile = req.user.profile
        serializer = UserProfileSerializer(profile)
        
        return Response({
            'success': True,
            'profile': serializer.data
        }, status=status.HTTP_200_OK)
        
    except UserProfile.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Profile not found.'
        }, status=status.HTTP_404_NOT_FOUND)


@extend_schema(**update_profile_schema)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_profile(req):
    """
    Update the current user's profile.

    Allows changing name, username, and email address. Email changes trigger
    a new verification email. Username is validated for uniqueness and format.

    Authentication is required via token in the request header.

    Args:
        req (Request): DRF request object with optional fields:
            - name (str)
            - username (str)
            - email (str)

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - profile (dict)

    Status Codes:
        200 OK: Profile updated successfully.
        400 Bad Request: Invalid data or duplicate email/username.
        500 Internal Server Error: Unexpected error during update.
    """

    try:
        profile = req.user.profile
        user = req.user
        was_updated = False
        
        # update name
        if 'name' in req.data and profile.name != req.data['name']:
            profile.name = req.data['name']
            was_updated = True
        
        # update username
        if 'username' in req.data and user.username != req.data['username']:
            new_username = req.data['username']

            # check if username already exists
            if User.objects.filter(username=new_username).exclude(id=user.id).exists():
                return Response({
                    'success': False,
                    'message': 'Username already exists.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # validate username format (optional)
            if not re.match(r'^[a-zA-Z0-9_]+$', new_username):
                return Response({
                    'success': False, 
                    'message': 'Username can only contain letters, numbers, and underscores.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user.username = new_username
            user.save()
            was_updated = True
        
        # update email
        if 'email' in req.data and user.email != req.data['email']:
            new_email = req.data['email']
            if User.objects.filter(email=new_email).exclude(id=user.id).exists():
                return Response({
                    'success': False,
                    'message': 'Email already exists.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user.email = new_email
            user.save()
            
            # reset email verification
            profile.email_verified = False
            was_updated = True
            
            # send new verification email
            send_verification_email(user)
        
        # only update the timestamp if an actual change was made
        if was_updated:
            profile.updated_at = timezone.now()
        
        profile.save()
        
        serializer = UserProfileSerializer(profile)
        return Response({
            'success': True,
            'message': 'Profile updated successfully.' + (' Please verify your new email address.' if not profile.email_verified else ''),
            'profile': serializer.data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Profile update error: {str(e)}")
        return Response({
            'success': False,
            'message': 'Profile update failed.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#################################################
#       PASSWORD MANAGEMENT ENDPOINTS
#################################################

@extend_schema(**change_password_schema)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(req):
    """
    Change the current user's password.

    Validates the old password and updates it to a new one. The new password
    must be different and meet strength requirements. All auth tokens are
    invalidated after update.

    Authentication is required via token in the request header.

    Args:
        req (Request): DRF request object with:
            - old_password (str)
            - new_password (str)
            - new_password_confirm (str)

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - errors (dict, optional)

    Status Codes:
        200 OK: Password changed successfully.
        400 Bad Request: Validation failed or passwords are the same.
    """

    serializer = ChangePasswordSerializer(data=req.data)
    
    if serializer.is_valid():
        user = req.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        
        # check old password
        if not user.check_password(old_password):
            return Response({
                'success': False,
                'message': 'Old password is incorrect.'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # check if new password is the same as old password
        if old_password == new_password:
            return Response({
                'success': False,
                'message': 'New password cannot be the same as old password.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # set new password
        user.set_password(new_password)
        user.save()
        
        # update the user profile's updated_at timestamp
        profile = user.profile
        profile.updated_at = timezone.now()

        with transaction.atomic():
            profile.save(update_fields=['updated_at'])
        
        # delete all tokens to force re-login
        Token.objects.filter(user=user).delete()
        
        return Response({
            'success': True,
            'message': 'Password changed successfully. Please login again.'
        }, status=status.HTTP_200_OK)
    
    return Response({
        'success': False,
        'message': 'Invalid data provided.',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(**forgot_password_schema)
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(req):
    """
    Send a password reset email.

    Sends a password reset link to the user's email if the account exists.
    Always returns success to avoid email enumeration.

    Args:
        req (Request): DRF request object with:
            - email (str)

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - errors (dict, optional)

    Status Codes:
        200 OK: Request accepted (email sent if exists).
        400 Bad Request: Invalid email format.
    """

    serializer = PasswordResetRequestSerializer(data=req.data)

    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # send password reset email
            send_password_reset_email(user)
            
            return Response({
                'success': True,
                'message': 'Password reset email sent successfully.'
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            # don't reveal if email exists or not (security)
            return Response({
                'success': True,
                'message': 'Password reset email sent successfully.'
            }, status=status.HTTP_200_OK)
    
    return Response({
        'success': False,
        'message': 'Invalid email address.',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(**reset_password_schema)
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def reset_password(req, token):
    """
    Reset a user's password using a token.

    Handles both GET and POST requests:
    - GET: Verifies if the token is valid and unexpired.
    - POST: Validates and sets a new password using the token.

    All existing auth tokens are invalidated after a successful reset.

    Args:
        req (Request): DRF request object.
            POST must contain:
                - new_password (str)
                - new_password_confirm (str)
        token (UUID): Password reset token.

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - token (str, optional)
            - errors (dict, optional)

    Status Codes:
        200 OK: Token valid or password reset successful.
        400 Bad Request: Token expired/used or validation failed.
        404 Not Found: Token does not exist.
    """

    try:
        # find user profile with matching token
        profile = UserProfile.objects.get(password_reset_token=token)
        
        if not profile.is_password_token_valid():
            return Response({
                'success': False,
                'message': 'Password reset link has expired or already used.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # For GET requests, validate the token and return success
        if req.method == 'GET':
            return Response({
                'success': True,
                'message': 'Token is valid. Please submit your new password.',
                'token': str(token)
            }, status=status.HTTP_200_OK)
        
        # For POST requests, validate and process the new password
        serializer = PasswordResetSerializer(data=req.data)
        
        if serializer.is_valid():
            new_password = serializer.validated_data['new_password']
            
            # get user
            user = profile.user

            # check if new password is the same as current password
            if user.check_password(new_password):
                return Response({
                    'success': False,
                    'message': 'New password cannot be the same as your current password.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # reset password
            user.set_password(new_password)
            user.save()

            # update user profile's updated_at timestamp after Password Reset
            profile.updated_at = timezone.now()
            
            # mark token as used
            profile.use_password_token()
            
            # delete all user tokens to force re-login
            Token.objects.filter(user=user).delete()
            
            return Response({
                'success': True,
                'message': 'Password reset successfully. Please login with your new password.'
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'message': 'Invalid data provided.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except UserProfile.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Invalid password reset token.'
        }, status=status.HTTP_400_BAD_REQUEST)


#################################################
#       ACCOUNT MANAGEMENT ENDPOINTS
#################################################

@extend_schema(**delete_account_schema)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_account(req):
    """
    Permanently delete the current user's account.

    Deletes the user and all associated data after verifying the password.
    This action is irreversible and results in immediate logout.

    Authentication is required via token in the request header.

    Args:
        req (Request): DRF request object with:
            - password (str)

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)

    Status Codes:
        200 OK: Account deleted successfully.
        400 Bad Request: Password missing or incorrect.
        500 Internal Server Error: Unexpected error during deletion.
    """

    password = req.data.get('password')
    
    if not password:
        return Response({
            'success': False,
            'message': 'Password is required to delete account.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = req.user
    
    if not user.check_password(password):
        return Response({
            'success': False,
            'message': 'Incorrect password.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # delete user (profile will be deleted automatically due to CASCADE)
        user.delete()
        
        return Response({
            'success': True,
            'message': 'Account deleted successfully.'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Account deletion error: {str(e)}")
        return Response({
            'success': False,
            'message': 'Account deletion failed.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#################################################
#           TWO-FACTOR AUTHENTICATION ENDPOINTS
#################################################

@extend_schema(**verify_2fa_schema)
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_2fa(req):
    """
    Verify a 2FA code during login

    This endpoint is called after initial username/password authentication when
    2FA is enabled. It requires a temporary token and 2FA code.

    Args:
        req (Request): DRF request object with:
            - temp_token (str): Temporary token from login endpoint
            - code (str): 2FA code from authenticator app or backup code

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - token (str): Final authentication token on success
            - user (dict): User information

    Status Codes:
        200 OK: Code verified successfully
        400 Bad Request: Invalid code or token
    """
    temp_token = req.data.get('temp_token')
    code = req.data.get('code')
    
    if not temp_token or not code:
        return Response({
            'success': False,
            'message': 'Missing temporary token or verification code.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Get the user associated with this temporary token
        token_obj = Token.objects.get(key=temp_token)
        user = token_obj.user
        
        # Verify the 2FA code
        if user.profile.verify_2fa_code(code):
            # Code is valid, update login time and return full access
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Return the same token for consistency
            return Response({
                'success': True,
                'message': 'Two-factor authentication successful.',
                'token': token_obj.key,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'name': user.profile.name,
                    'email_verified': user.profile.email_verified,
                    'two_factor_enabled': user.profile.two_factor_enabled
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'success': False,
                'message': 'Invalid verification code. Please try again.'
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Token.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Invalid temporary token.'
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(**two_factor_setup_schema)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def setup_2fa(req):
    """
    Begin setup of 2FA

    Generates a new 2FA secret and returns it with a QR code for the user
    to scan with their authenticator app.

    Args:
        req (Request): DRF request with authenticated user

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - secret (str): TOTP secret key
            - qr_code (str): QR code as base64 data URI
            - manual_entry_key (str): Secret key for manual entry

    Status Codes:
        200 OK: Setup information generated successfully
        400 Bad Request: 2FA already enabled
    """
    profile = req.user.profile
    
    # Check if 2FA is already enabled
    if profile.two_factor_enabled:
        return Response({
            'success': False,
            'message': 'Two-factor authentication is already enabled.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Generate a new secret key
    secret = profile.generate_2fa_secret()
    
    # Generate the QR code URI
    totp_uri = profile.get_totp_uri()
    qr_code = generate_qr_code_base64(totp_uri)
    
    return Response({
        'success': True,
        'message': 'Two-factor authentication setup initialized. Scan the QR code with your authenticator app.',
        'secret': secret,
        'qr_code': qr_code,
        'manual_entry_key': secret
    }, status=status.HTTP_200_OK)


@extend_schema(**two_factor_activate_schema)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def activate_2fa(req):
    """
    Activate 2FA after setup

    Verifies the provided code matches the temporary 2FA secret,
    then activates 2FA for the user's account.

    Args:
        req (Request): DRF request with:
            - code (str): Verification code from authenticator app

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - backup_codes (list): One-time use backup codes

    Status Codes:
        200 OK: 2FA successfully activated
        400 Bad Request: Invalid code or 2FA already enabled
    """
    serializer = TwoFactorSetupSerializer(data=req.data)
    
    if not serializer.is_valid():
        return Response({
            'success': False,
            'message': 'Invalid data provided.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    profile = req.user.profile
    code = serializer.validated_data['code']
    
    # Check if 2FA is already enabled
    if profile.two_factor_enabled:
        return Response({
            'success': False,
            'message': 'Two-factor authentication is already enabled.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Verify and activate 2FA
    if profile.activate_2fa(code):
        # Send notification email
        send_2fa_enabled_email(req.user)
        
        # Return backup codes
        backup_codes = profile.two_factor_backup_codes
        
        return Response({
            'success': True,
            'message': 'Two-factor authentication has been enabled successfully.',
            'backup_codes': backup_codes
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'success': False,
            'message': 'Invalid verification code. Please try again.'
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(**two_factor_disable_schema)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_2fa(req):
    """
    Disable 2FA for the user

    Requires password and 2FA code verification before disabling 2FA.

    Args:
        req (Request): DRF request with:
            - password (str): User's current password
            - code (str): Current 2FA code or backup code

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)

    Status Codes:
        200 OK: 2FA successfully disabled
        400 Bad Request: Invalid password/code or 2FA not enabled
    """
    serializer = TwoFactorDisableSerializer(data=req.data)
    
    if not serializer.is_valid():
        return Response({
            'success': False,
            'message': 'Invalid data provided.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    profile = req.user.profile
    password = serializer.validated_data['password']
    code = serializer.validated_data['code']
    
    # Check if 2FA is enabled
    if not profile.two_factor_enabled:
        return Response({
            'success': False,
            'message': 'Two-factor authentication is not enabled.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Verify password
    if not req.user.check_password(password):
        return Response({
            'success': False,
            'message': 'Invalid password.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Verify 2FA code
    if not profile.verify_2fa_code(code):
        return Response({
            'success': False,
            'message': 'Invalid verification code.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Disable 2FA
    profile.disable_2fa()
    
    # Send notification email
    send_2fa_disabled_email(req.user)
    
    return Response({
        'success': True,
        'message': 'Two-factor authentication has been disabled successfully.'
    }, status=status.HTTP_200_OK)


@extend_schema(**two_factor_backup_codes_schema)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def get_backup_codes(req):
    """
    Get or regenerate backup codes for 2FA

    GET: Returns current backup codes
    POST: Regenerates backup codes (requires 2FA verification)

    Args:
        req (Request): DRF request with:
            - code (str): Current 2FA code (POST only)

    Returns:
        Response: JSON response with:
            - success (bool)
            - message (str)
            - backup_codes (list): One-time use backup codes

    Status Codes:
        200 OK: Operation successful
        400 Bad Request: 2FA not enabled or invalid code
    """
    profile = req.user.profile
    
    # Check if 2FA is enabled
    if not profile.two_factor_enabled:
        return Response({
            'success': False,
            'message': 'Two-factor authentication is not enabled.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if req.method == 'GET':
        # Simply return current backup codes
        return Response({
            'success': True,
            'backup_codes': profile.two_factor_backup_codes or []
        }, status=status.HTTP_200_OK)
    
    # For POST - regenerate codes after verifying 2FA code
    code = req.data.get('code')
    
    if not code:
        return Response({
            'success': False,
            'message': 'Verification code is required.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if not profile.verify_2fa_code(code):
        return Response({
            'success': False,
            'message': 'Invalid verification code.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Generate new backup codes
    backup_codes = profile.generate_backup_codes()
    
    return Response({
        'success': True,
        'message': 'New backup codes generated.',
        'backup_codes': backup_codes
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def is_authenticated(request):
    return Response({
        'success': True,
        'message': 'User is authenticated.',
        'user': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'name': request.user.profile.name,
            'two_factor_enabled': request.user.profile.two_factor_enabled
        }
    }, status=status.HTTP_200_OK)

