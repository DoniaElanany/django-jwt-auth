from functools import wraps
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import PermissionDenied


def require_authentication(view_func):
    """Decorator to require authentication"""
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return view_func(self, request, *args, **kwargs)
    return wrapper


def require_admin(view_func):
    """Decorator to require admin or super_admin role"""
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not request.user.is_admin():
            return Response(
                {'error': 'Admin privileges required'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return view_func(self, request, *args, **kwargs)
    return wrapper


def require_super_admin(view_func):
    """Decorator to require super_admin role only"""
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not request.user.is_super_admin():
            return Response(
                {'error': 'Super admin privileges required'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return view_func(self, request, *args, **kwargs)
    return wrapper


def check_user_modification_permission(request_user, target_user):
    """
    Check if request_user has permission to modify target_user
    
    Rules:
    - Super admin can modify anyone EXCEPT other super admins (including themselves)
    - Regular admin can only modify regular users (user_type=user)
    - Regular admin CANNOT modify other admins or super admin
    - Users cannot modify others
    
    Returns: (allowed: bool, error_message: str)
    """
    # Cannot modify any super admin
    if target_user.is_super_admin():
        return False, "Cannot modify super admin users"
    
    # Super admin can modify anyone except super admins
    if request_user.is_super_admin():
        return True, None
    
    # Regular admin can only modify regular users
    if request_user.is_admin():
        if target_user.is_admin():
            return False, "Regular admins cannot modify other admins"
        
        # Can modify regular users
        return True, None
    
    # Regular users can only modify themselves
    if request_user.id != target_user.id:
        return False, "You can only modify your own profile"
    
    return True, None


def check_user_type_change_permission(request_user, target_user, new_user_type):
    """
    Check if request_user has permission to change target_user's type to new_user_type
    
    Rules:
    - Only super admin can change user types to/from admin or super_admin
    - Regular admin can change regular user types (but not to admin or super_admin)
    - Cannot change super admin's type
    
    Returns: (allowed: bool, error_message: str)
    """
    # Cannot change super admin's type
    if target_user.is_super_admin():
        return False, "Cannot change user type of super admin"
    
    # Super admin can change any type (except their own to prevent lockout)
    if request_user.is_super_admin():
        if request_user.id == target_user.id and new_user_type.type_name != 'super_admin':
            return False, "Cannot change your own super admin type"
        return True, None
    
    # Regular admin restrictions
    if request_user.is_admin():
        # Cannot promote to admin or super_admin
        if new_user_type.type_name in ['admin', 'super_admin']:
            return False, "Regular admins cannot promote users to admin or super_admin"
        
        # Cannot change other admins' types
        if target_user.is_admin():
            return False, "Regular admins cannot modify other admins"
        
        return True, None
    
    # Regular users cannot change types
    return False, "Insufficient permissions to change user types"
