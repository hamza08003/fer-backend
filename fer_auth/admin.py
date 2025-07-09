from django.contrib import admin
from django.utils import timezone
from django.urls import reverse
from django.utils.formats import date_format
from django.utils.html import format_html
from .models import UserProfile


admin.site.site_header = "FER Admin"
admin.site.site_title = "FER Admin Portal"
admin.site.index_title = "Welcome to FER Admin Portal"


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['name', 'username_link', 'email', 'email_verified', 'last_login_display', 'updated_at_display', 'email_token_status', 'password_token_status']
    list_filter = ['email_verified', 'updated_at']
    search_fields = ['name', 'user__username', 'user__email']
    readonly_fields = ['last_login_display', 'updated_at', 'email_verification_token', 'email_token_expires_at', 'password_reset_token', 'password_token_expires_at', 'password_token_used']
    fieldsets = [
        (None, {'fields': ['user', 'name', 'email_verified']}),
        ('Timestamps', {'fields': ['last_login_display', 'updated_at'], 'classes': ['collapse']}),
        ('Email Verification', {'fields': ['email_verification_token', 'email_token_expires_at'], 'classes': ['collapse']}),
        ('Password Reset', {'fields': ['password_reset_token', 'password_token_expires_at', 'password_token_used'], 'classes': ['collapse']}),
    ]
    
    def username_link(self, obj):
        url = reverse('admin:auth_user_change', args=[obj.user.id])
        return format_html('<a href="{}">{}</a>', url, obj.user.username)
    username_link.short_description = 'Username'
    
    def email(self, obj):
        return obj.user.email
    email.admin_order_field = 'user__email'
    
    def updated_at_display(self, obj):
        if obj.updated_at is None:
            return "Not Updated Yet"
        return obj.updated_at
    updated_at_display.short_description = 'Last Updated'
    updated_at_display.admin_order_field = 'updated_at'

    def last_login_display(self, obj):
        if obj.user.last_login is None:
            return "Never Logged In"
        return date_format(obj.user.last_login, format='DATETIME_FORMAT', use_l10n=True)
    last_login_display.short_description = 'Last Login'
    last_login_display.admin_order_field = 'user__last_login'
    
    def email_token_status(self, obj):
        if not obj.email_verification_token:
            return "No Token"
        elif obj.is_email_token_valid():
            return format_html('<span style="color: green;">Active</span>')
        else:
            return format_html('<span style="color: red;">Expired</span>')
    email_token_status.short_description = 'Email Token'
    
    def password_token_status(self, obj):
        if not obj.password_reset_token:
            return "No Token"
        elif obj.password_token_used:
            return format_html('<span style="color: gray;">Used</span>')
        elif obj.is_password_token_valid():
            return format_html('<span style="color: green;">Active</span>')
        else:
            return format_html('<span style="color: red;">Expired</span>')
    password_token_status.short_description = 'Password Token'
    
    actions = ['delete_expired_tokens']
    
    def delete_expired_tokens(self, request, queryset):
        count = 0
        for profile in queryset:
            if profile.email_verification_token and not profile.is_email_token_valid():
                profile.invalidate_email_token()
                count += 1
            if profile.password_reset_token and (not profile.is_password_token_valid() or profile.password_token_used):
                profile.invalidate_password_token()
                count += 1
        self.message_user(request, f"Cleared {count} expired tokens.")
    delete_expired_tokens.short_description = "Clear expired tokens"
    