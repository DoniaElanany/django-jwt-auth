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
    # Permission system views
    JobRoleListView,
    JobRoleDetailView,
    JobRoleDutyRolesView,
    JobRoleUsersView,
    AssignDutyRoleView,
    RemoveDutyRoleView,
    DutyRoleListView,
    DutyRoleDetailView,
    ResourceListView,
    ResourceDetailView,
    DutyRolePermissionView,
    DutyRolePermissionListView,
    DutyRolePermissionDeleteView,
    UserPermissionOverrideView,
    UserPermissionOverrideListView,
    UserPermissionOverrideDeleteView,
    UserEffectivePermissionsView
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
    path('permissions/', UserEffectivePermissionsView.as_view(), name='user_permissions'),
    
    # Admin user management endpoints
    path('admin/users/', AdminUserListView.as_view(), name='admin_user_list'),
    path('admin/users/<int:user_id>/', AdminUserDetailView.as_view(), name='admin_user_detail'),
    path('admin/users/<int:user_id>/type/', ChangeUserTypeView.as_view(), name='change_user_type'),
    
    # Admin user type endpoints
    path('admin/user-types/', UserTypeListView.as_view(), name='user_type_list'),
    
    # Password reset flow (user requests, super admin sets temporary password)
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('admin/password-reset/', SuperAdminPasswordResetView.as_view(), name='super_admin_password_reset'),
    
    # Job Role Management (Admin only)
    path('admin/job-roles/', JobRoleListView.as_view(), name='job_role_list'),
    path('admin/job-roles/<int:pk>/', JobRoleDetailView.as_view(), name='job_role_detail'),
    path('admin/job-roles/<int:pk>/duty-roles/', JobRoleDutyRolesView.as_view(), name='job_role_duty_roles'),
    path('admin/job-roles/<int:pk>/users/', JobRoleUsersView.as_view(), name='job_role_users'),
    path('admin/job-roles/<int:job_role_pk>/assign-duty-role/', AssignDutyRoleView.as_view(), name='assign_duty_role'),
    path('admin/job-roles/<int:job_role_pk>/remove-duty-role/<int:duty_role_pk>/', RemoveDutyRoleView.as_view(), name='remove_duty_role'),
    
    # Duty Role Management (Admin only)
    path('admin/duty-roles/', DutyRoleListView.as_view(), name='duty_role_list'),
    path('admin/duty-roles/<int:pk>/', DutyRoleDetailView.as_view(), name='duty_role_detail'),
    
    # Resource Management (Admin only)
    path('admin/resources/', ResourceListView.as_view(), name='resource_list'),
    path('admin/resources/<int:pk>/', ResourceDetailView.as_view(), name='resource_detail'),
    
    # Duty Role Permission Management (Admin only)
    path('admin/duty-role-permissions/', DutyRolePermissionView.as_view(), name='duty_role_permission'),
    path('admin/duty-role-permissions/list/', DutyRolePermissionListView.as_view(), name='duty_role_permission_list'),
    path('admin/duty-role-permissions/<int:pk>/', DutyRolePermissionDeleteView.as_view(), name='duty_role_permission_delete'),
    
    # User Permission Override Management (Admin only)
    path('admin/user-overrides/', UserPermissionOverrideView.as_view(), name='user_override'),
    path('admin/user-overrides/list/', UserPermissionOverrideListView.as_view(), name='user_override_list'),
    path('admin/user-overrides/<int:pk>/', UserPermissionOverrideDeleteView.as_view(), name='user_override_delete'),
]

