from django.urls import path
from .views import (
    LoginView,
    RegisterView,
    UserProfileView,
    ChangePasswordView,
    AdminUserListView,
    AdminUserDetailView,
    ChangeUserTypeView,
    UserTypeListView,
    PasswordResetRequestView,
    SuperAdminPasswordResetView
)
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    # Public endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User profile endpoints (authenticated users)
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    
    # Admin user management endpoints
    path('admin/users/', AdminUserListView.as_view(), name='admin_user_list'),
    path('admin/users/<int:user_id>/', AdminUserDetailView.as_view(), name='admin_user_detail'),
    path('admin/users/<int:user_id>/type/', ChangeUserTypeView.as_view(), name='change_user_type'),
    
    # Admin user type endpoints
    path('admin/user-types/', UserTypeListView.as_view(), name='user_type_list'),
    
    # Password reset flow (user requests, super admin sets temporary password)
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('admin/password-reset/', SuperAdminPasswordResetView.as_view(), name='super_admin_password_reset'),
]

