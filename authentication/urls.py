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
    SuperAdminPasswordResetView,
    # Page-based permission system views
    JobRoleListCreateView,
    JobRolePageManagementView,
    JobRolePagesView,
    JobRolePageDetailView,
    PageListCreateView,
    PageDetailView,
    PageActionListCreateView,
    PageActionDetailView,
    UserPermissionsView,
    UserDeniedActionsView,
    UserDenyActionView,
    UserRemoveDenialView,
    UserBulkDenyActionsView,
    UserBulkRemoveDenialsView,
    UserJobRoleView,
    CheckPermissionView,
    BulkCheckPermissionsView,
    MyPermissionsView,
    MyPagesView,
)
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    # Public endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User profile endpoints
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    
    # Admin user management
    path('admin/users/', AdminUserListView.as_view(), name='admin_user_list'),
    path('admin/users/<int:user_id>/', AdminUserDetailView.as_view(), name='admin_user_detail'),
    path('admin/users/<int:user_id>/type/', ChangeUserTypeView.as_view(), name='change_user_type'),
    path('admin/user-types/', UserTypeListView.as_view(), name='user_type_list'),
    
    # Password reset
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('admin/password-reset/', SuperAdminPasswordResetView.as_view(), name='super_admin_password_reset'),
    
    # Job Roles (Super Admin)
    path('admin/job-roles/', JobRoleListCreateView.as_view(), name='job_roles'),
    path('admin/job-roles/<int:pk>/', JobRolePageManagementView.as_view(), name='job_role_detail'),
    path('admin/job-roles/<int:pk>/pages/', JobRolePagesView.as_view(), name='job_role_pages'),
    path('admin/job-roles/<int:pk>/pages/<int:page_id>/', JobRolePageDetailView.as_view(), name='job_role_page_unlink'),
    
    # Pages (Super Admin)
    path('admin/pages/', PageListCreateView.as_view(), name='pages'),
    path('admin/pages/<int:pk>/', PageDetailView.as_view(), name='page_detail'),
    path('admin/pages/<int:page_id>/actions/', PageActionListCreateView.as_view(), name='page_actions'),
    path('admin/pages/<int:page_id>/actions/<int:action_id>/', PageActionDetailView.as_view(), name='page_action_detail'),
    
    # User Permissions
    path('users/<int:user_id>/permissions/', UserPermissionsView.as_view(), name='user_permissions'),
    path('users/<int:user_id>/denied-actions/', UserDeniedActionsView.as_view(), name='user_denied_actions'),
    path('users/<int:user_id>/deny-action/', UserDenyActionView.as_view(), name='deny_action'),
    path('users/<int:user_id>/denied-actions/<int:denial_id>/', UserRemoveDenialView.as_view(), name='remove_denial'),
    path('users/<int:user_id>/deny-actions/bulk/', UserBulkDenyActionsView.as_view(), name='bulk_deny_actions'),
    path('users/<int:user_id>/denied-actions/bulk/', UserBulkRemoveDenialsView.as_view(), name='bulk_remove_denials'),
    path('users/<int:user_id>/job-role/', UserJobRoleView.as_view(), name='user_job_role'),
    
    # Permission Checks
    path('check-permission/', CheckPermissionView.as_view(), name='check_permission'),
    path('check-permissions/bulk/', BulkCheckPermissionsView.as_view(), name='bulk_check_permissions'),
    
    # Current User
    path('me/permissions/', MyPermissionsView.as_view(), name='my_permissions'),
    path('me/pages/', MyPagesView.as_view(), name='my_pages'),
]
