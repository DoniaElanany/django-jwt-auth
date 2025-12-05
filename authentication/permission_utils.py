"""
Permission resolution logic for role-based access control
"""
from .models import CustomUser, DutyRolePermission, UserPermissionOverride


def user_has_permission(user, resource_name, action):
    """
    Check if a user has permission to perform an action on a resource.
    
    Args:
        user: CustomUser instance
        resource_name: str - name of the resource (e.g., 'invoice', 'payment')
        action: str - one of 'create', 'read', 'update', 'delete'
    
    Returns:
        bool - True if user has permission, False otherwise
    
    Logic:
        1. Admin and Super Admin bypass permission checks (full access)
        2. User must have a job role to have any permissions
        3. Get duty roles linked to user's job role
        4. For each duty role, check for user-specific overrides first
        5. If no override, use default permission from DutyRolePermission
        6. If ANY duty role grants permission, user has permission
    """
    # Admin and Super Admin have full access
    if user.is_admin():
        return True
    
    # User must have a job role
    if not user.job_role:
        return False
    
    # Validate action
    if action not in ['create', 'read', 'update', 'delete']:
        raise ValueError(f"Invalid action: {action}. Must be one of: create, read, update, delete")
    
    # Get duty roles for this job role
    duty_roles = user.job_role.duty_roles.all()
    
    if not duty_roles.exists():
        return False
    
    # Check each duty role
    for duty_role in duty_roles:
        # Check for user-specific override first
        try:
            override = UserPermissionOverride.objects.get(
                user=user,
                duty_role=duty_role,
                resource__name=resource_name
            )
            
            # Get the override value for this action
            permission_value = getattr(override, f'can_{action}')
            
            # NULL means use default, so we skip to check default
            if permission_value is not None:
                if permission_value:  # Explicitly allowed
                    return True
                # Explicitly denied, continue to next duty role
                continue
                
        except UserPermissionOverride.DoesNotExist:
            pass  # No override, check default
        
        # No override or override is NULL, use default from duty role
        try:
            default_perm = DutyRolePermission.objects.get(
                duty_role=duty_role,
                resource__name=resource_name
            )
            
            if getattr(default_perm, f'can_{action}'):
                return True
                
        except DutyRolePermission.DoesNotExist:
            continue  # No permission defined for this duty role + resource
    
    return False


def get_user_permissions(user, resource_name=None):
    """
    Get all effective permissions for a user.
    
    Args:
        user: CustomUser instance
        resource_name: str (optional) - if provided, get permissions only for this resource
    
    Returns:
        dict - Structure:
        {
            'resource_name': {
                'can_create': bool,
                'can_read': bool,
                'can_update': bool,
                'can_delete': bool
            }
        }
    """
    # Admin and Super Admin have full access
    if user.is_admin():
        if resource_name:
            return {
                resource_name: {
                    'can_create': True,
                    'can_read': True,
                    'can_update': True,
                    'can_delete': True
                }
            }
        # Return full access for all resources
        return {'_admin': 'full_access'}
    
    # User must have a job role
    if not user.job_role:
        return {}
    
    permissions = {}
    duty_roles = user.job_role.duty_roles.all()
    
    # Get all default permissions for all duty roles
    duty_role_permissions = DutyRolePermission.objects.filter(
        duty_role__in=duty_roles
    )
    
    if resource_name:
        duty_role_permissions = duty_role_permissions.filter(resource__name=resource_name)
    
    # Build permissions map
    for perm in duty_role_permissions:
        res_name = perm.resource.name
        if res_name not in permissions:
            permissions[res_name] = {
                'can_create': False,
                'can_read': False,
                'can_update': False,
                'can_delete': False
            }
        
        # Union of permissions (if any duty role grants, user has it)
        permissions[res_name]['can_create'] = permissions[res_name]['can_create'] or perm.can_create
        permissions[res_name]['can_read'] = permissions[res_name]['can_read'] or perm.can_read
        permissions[res_name]['can_update'] = permissions[res_name]['can_update'] or perm.can_update
        permissions[res_name]['can_delete'] = permissions[res_name]['can_delete'] or perm.can_delete
    
    # Apply user-specific overrides
    overrides = UserPermissionOverride.objects.filter(user=user)
    if resource_name:
        overrides = overrides.filter(resource__name=resource_name)
    
    for override in overrides:
        res_name = override.resource.name
        if res_name not in permissions:
            permissions[res_name] = {
                'can_create': False,
                'can_read': False,
                'can_update': False,
                'can_delete': False
            }
        
        # Apply overrides (NULL means keep current value)
        if override.can_create is not None:
            permissions[res_name]['can_create'] = override.can_create
        if override.can_read is not None:
            permissions[res_name]['can_read'] = override.can_read
        if override.can_update is not None:
            permissions[res_name]['can_update'] = override.can_update
        if override.can_delete is not None:
            permissions[res_name]['can_delete'] = override.can_delete
    
    return permissions


def require_permission(resource_name, action):
    """
    Decorator to check if user has permission before executing view.
    
    Usage:
        @require_permission('invoice', 'create')
        def create_invoice(request):
            ...
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                from rest_framework.response import Response
                from rest_framework import status
                return Response(
                    {'error': 'Authentication required'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            if not user_has_permission(request.user, resource_name, action):
                from rest_framework.response import Response
                from rest_framework import status
                return Response(
                    {'error': f'You do not have permission to {action} {resource_name}'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
