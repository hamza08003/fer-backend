from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import base64
import qrcode
import io


def send_verification_email(user):
    """
    Send email verification link with HTML formatting
    """
    # Create verification token
    token = user.profile.create_email_verification_token()
    verification_url = f"{settings.SITE_DOMAIN}/fer/auth/verify-email/{token}/"
    
    # context for email template
    context = {
        'name': user.profile.name,
        'verification_url': verification_url,
    }
    
    # render HTML email
    html_message = render_to_string('fer_auth/email_verification.html', context)
    plain_message = strip_tags(html_message)
    
    # create email
    email = EmailMultiAlternatives(
        subject='Verify Your Email Address',
        body=plain_message,
        from_email=settings.EMAIL_HOST_USER,
        to=[user.email]
    )
    
    # attach HTML content
    email.attach_alternative(html_message, "text/html")
    email.send()


def send_password_reset_email(user):
    """
    Send password reset link with HTML formatting
    """
    # Create reset token
    token = user.profile.create_password_reset_token()
    reset_url = f"{settings.SITE_DOMAIN}/fer/auth/reset-password/{token}/"

    # context for email template
    context = {
        'name': user.profile.name,
        'reset_url': reset_url,
    }
    
    # render HTML email
    html_message = render_to_string('fer_auth/password_reset.html', context)
    plain_message = strip_tags(html_message)
    
    # create email
    email = EmailMultiAlternatives(
        subject='Reset Your Password',
        body=plain_message,
        from_email=settings.EMAIL_HOST_USER,
        to=[user.email]
    )
    
    # attach HTML content
    email.attach_alternative(html_message, "text/html")
    email.send()


def generate_qr_code_base64(uri):
    """
    Generate a QR code as base64 from a URI
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    
    # save to bytes buffer
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    
    # convert to base64
    img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return f"data:image/png;base64,{img_str}"


def send_2fa_enabled_email(user):
    """
    Send email notification that 2FA was enabled
    """
    context = {
        'name': user.profile.name,
    }
    
    html_message = render_to_string('fer_auth/2fa_enabled.html', context)
    plain_message = strip_tags(html_message)
    
    email = EmailMultiAlternatives(
        subject='Two-Factor Authentication Enabled',
        body=plain_message,
        from_email=settings.EMAIL_HOST_USER,
        to=[user.email]
    )
    
    email.attach_alternative(html_message, "text/html")
    email.send()


def send_2fa_disabled_email(user):
    """
    Send email notification that 2FA was disabled
    """
    context = {
        'name': user.profile.name,
    }
    
    html_message = render_to_string('fer_auth/2fa_disabled.html', context)
    plain_message = strip_tags(html_message)
    
    email = EmailMultiAlternatives(
        subject='Two-Factor Authentication Disabled',
        body=plain_message,
        from_email=settings.EMAIL_HOST_USER,
        to=[user.email]
    )
    
    email.attach_alternative(html_message, "text/html")
    email.send()
    