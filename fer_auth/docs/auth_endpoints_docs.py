from drf_spectacular.utils import OpenApiExample, OpenApiParameter, OpenApiResponse
from drf_spectacular.types import OpenApiTypes
from ..serializers import *


# -------------------------
#  AUTHENTICATION SCHEMAS
# -------------------------

registration_schema = {
    "tags": ["Authentication"],
    "request": UserRegistrationSerializer,
    "responses": {
        201: OpenApiResponse(
            description="Registration successful",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"},
                "user": {"type": "object", "properties": {
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                    "name": {"type": "string"}
                }}
            }}
        ),
        400: OpenApiResponse(description="Invalid input"),
        500: OpenApiResponse(description="Server error"),
    },
    "examples": [
        OpenApiExample(
            "Registration Example",
            value={
                "username": "newuser123",
                "email": "user@example.com",
                "name": "New User",
                "password": "SecurePassword@123",
                "password_confirm": "SecurePassword@123"
            },
            request_only=True,
        )
    ]
}

login_schema = {
    "tags": ["Authentication"],
    "request": UserLoginSerializer,
    "responses": {
        200: OpenApiResponse(
            description="Login successful",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"},
                "token": {"type": "string"},
                "user": {"type": "object"}
            }}
        ),
        400: OpenApiResponse(description="Invalid credentials")
    },
    "examples": [
        OpenApiExample(
            "Login Example",
            value={
                "username": "existinguser",
                "password": "YourPassword123"
            },
            request_only=True,
        )
    ]
}

logout_schema = {
    "tags": ["Authentication"],
    "responses": {
        200: OpenApiResponse(
            description="Logout successful",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"}
            }}
        ),
        400: OpenApiResponse(description="Not logged in")
    }
}

# -------------------------
# EMAIL VERIFICATION SCHEMAS
# -------------------------

verify_email_schema = {
    "tags": ["Email Verification"],
    "responses": {
        200: OpenApiResponse(
            description="Email verified successfully",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"}
            }}
        ),
        400: OpenApiResponse(description="Invalid or expired token")
    },
    "parameters": [
        OpenApiParameter(
            name="token",
            location=OpenApiParameter.PATH,
            required=True,
            description="Email verification token",
            type=OpenApiTypes.UUID
        )
    ]
}

resend_verification_schema = {
    "tags": ["Email Verification"],
    "request": {
        "type": "object",
        "properties": {
            "email": {"type": "string", "format": "email"}
        }
    },
    "responses": {
        200: OpenApiResponse(
            description="Verification email sent successfully",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"}
            }}
        ),
        400: OpenApiResponse(description="Email already verified or does not exist")
    },
    "examples": [
        OpenApiExample(
            "Resend Email Example",
            value={"email": "user@example.com"},
            request_only=True,
        )
    ]
}

# -------------------------
# PROFILE MANAGEMENT SCHEMAS
# -------------------------

profile_schema = {
    "tags": ["Profile Management"],
    "responses": {
        200: OpenApiResponse(
            description="User profile retrieved successfully",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "profile": {"type": "object"}
            }}
        ),
        404: OpenApiResponse(description="Profile not found")
    }
}

update_profile_schema = {
    "tags": ["Profile Management"],
    "request": {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "username": {"type": "string"},
            "email": {"type": "string", "format": "email"}
        }
    },
    "responses": {
        200: OpenApiResponse(
            description="Profile updated successfully",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"},
                "profile": {"type": "object"}
            }}
        ),
        400: OpenApiResponse(description="Invalid data or username/email already exists"),
        500: OpenApiResponse(description="Server error")
    },
    "examples": [
        OpenApiExample(
            "Update Profile Example",
            value={
                "name": "Updated Name",
                "username": "newusername",
                "email": "newemail@example.com"
            },
            request_only=True,
        )
    ]
}

# -------------------------
# PASSWORD MANAGEMENT SCHEMAS
# -------------------------

change_password_schema = {
    "tags": ["Password Management"],
    "request": ChangePasswordSerializer,
    "responses": {
        200: OpenApiResponse(
            description="Password changed successfully",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"}
            }}
        ),
        400: OpenApiResponse(description="Invalid old password or same as new")
    },
    "examples": [
        OpenApiExample(
            "Change Password Example",
            value={
                "old_password": "OldPassword123",
                "new_password": "NewPassword456",
                "new_password_confirm": "NewPassword456"
            },
            request_only=True,
        )
    ]
}

forgot_password_schema = {
    "tags": ["Password Management"],
    "request": PasswordResetRequestSerializer,
    "responses": {
        200: OpenApiResponse(
            description="Password reset email sent",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"}
            }}
        ),
        400: OpenApiResponse(description="Invalid email format")
    },
    "examples": [
        OpenApiExample(
            "Forgot Password Example",
            value={"email": "user@example.com"},
            request_only=True,
        )
    ]
}

reset_password_schema = {
    "tags": ["Password Management"],
    "request": PasswordResetSerializer,
    "responses": {
        200: OpenApiResponse(
            description="Password reset successful",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"}
            }}
        ),
        400: OpenApiResponse(description="Invalid token or password")
    },
    "parameters": [
        OpenApiParameter(
            name="token",
            location=OpenApiParameter.PATH,
            required=True,
            description="Password reset token",
            type=OpenApiTypes.UUID
        )
    ],
    "examples": [
        OpenApiExample(
            "Reset Password Example",
            value={
                "new_password": "NewSecurePassword123!",
                "new_password_confirm": "NewSecurePassword123!"
            },
            request_only=True,
        )
    ]
}

# -------------------------
# ACCOUNT MANAGEMENT SCHEMAS
# -------------------------

delete_account_schema = {
    "tags": ["Account Management"],
    "request": {
        "type": "object",
        "properties": {
            "password": {"type": "string"}
        }
    },
    "responses": {
        200: OpenApiResponse(
            description="Account deleted successfully",
            response={"type": "object", "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"}
            }}
        ),
        400: OpenApiResponse(description="Invalid password"),
        500: OpenApiResponse(description="Server error")
    },
    "examples": [
        OpenApiExample(
            "Delete Account Example",
            value={"password": "YourCurrentPassword"},
            request_only=True,
        )
    ]
}
