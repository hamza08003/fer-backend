from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags


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
    