from django.urls import path, include
from . import views


urlpatterns = [
    path('fer/v1/', include([
        # Authentication endpoints
        path('auth/', include([
            path('status/', views.check_auth_status, name='auth_status'),
            path('register/', views.register, name='register'),
            path('login/', views.login, name='login'),
            path('logout/', views.logout, name='logout'),
            path('verify-2fa/', views.verify_2fa, name='verify_2fa'),
        ])),
        
        # User resources
        path('users/', include([
            path('me/', views.profile, name='profile'),
            path('me/update/', include([
                path('profile/', views.update_profile, name='update_profile'),
                path('password/', views.change_password, name='change_password'),
            ])),
            path('me/2fa/', include([
                path('setup/', views.setup_2fa, name='setup_2fa'),
                path('activate/', views.activate_2fa, name='activate_2fa'),
                path('disable/', views.disable_2fa, name='disable_2fa'),
                path('backup-codes/', views.get_backup_codes, name='get_backup_codes'),
            ])),
        ])),
        
        # Account operations
        path('account/', include([
            path('verification/email/<uuid:token>/', views.verify_email, name='verify_email'),
            path('verification/email/resend/', views.resend_verification, name='resend_verification'),
            path('password/reset/', views.forgot_password, name='forgot_password'),
            path('password/reset/<uuid:token>/', views.reset_password, name='reset_password'),
            path('delete/', views.delete_account, name='delete_account'),
        ])),
    ])),
]
