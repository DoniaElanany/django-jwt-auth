from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.core.exceptions import PermissionDenied, ValidationError
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from django.db import transaction
from .models import (
    CustomUser, UserType, JobRole,
    Page, PageAction, JobRolePage, UserActionDenial
)
from .serializers import (
    UserRegistrationSerializer,
    UserProfileSerializer,
    AdminUserSerializer,
    ChangeUserTypeSerializer,
    UserTypeSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    SuperAdminPasswordResetSerializer,
    # Page-based permission serializers
    JobRoleSerializer,
    PageSerializer,
    PageListSerializer,
    PageActionSerializer,
    JobRoleDetailSerializer,
    JobRoleListSerializer,
    LinkPagesToJobRoleSerializer,
    UserActionDenialSerializer,
    DenyActionSerializer,
    BulkDenyActionsSerializer,
    BulkRemoveDenialsSerializer,
    AssignJobRoleSerializer,
    CheckPermissionSerializer,
    BulkCheckPermissionsSerializer,
)
from .permissions import (
    require_authentication,
    require_admin,
    require_super_admin,
    check_user_modification_permission,
    check_user_type_change_permission
)
from .permission_utils import (
    user_can_perform_action,
    get_user_page_permissions,
    get_user_denied_actions,
    get_user_accessible_pages
)


class RegisterView(APIView):
    """Public endpoint for user registration"""
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'User registered successfully',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'phone_number': user.phone_number,
                    'user_type': user.user_type.type_name
                },
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """Public endpoint for user login"""
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = authenticate(username=email, password=password)
        
        if user is None:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'user_type': user.user_type.type_name
            },
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_200_OK)


class UserProfileView(APIView):
    """Endpoint for users to view/update their own profile"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get own profile"""
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request):
        """Update own profile"""
        # Super admins cannot update their own profile
        if request.user.is_super_admin():
            return Response(
                {'error': 'Super admins cannot modify their own profile'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully',
                'user': serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    """Endpoint for authenticated users to change their password"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Change password for authenticated user"""
        # Super admins cannot change their own password
        if request.user.is_super_admin():
            return Response(
                {'error': 'Super admins cannot change their own password'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            # Set new password
            request.user.set_password(serializer.validated_data['new_password'])
            request.user.save()
            
            return Response({
                'message': 'Password changed successfully. Please login again with your new password.'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminUserListView(APIView):
    """Admin endpoint to list all users"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request):
        """List all users (admin only)"""
        users = CustomUser.objects.all().select_related('user_type').order_by('-created_at')
        serializer = AdminUserSerializer(users, many=True)
        return Response({
            'count': users.count(),
            'users': serializer.data
        }, status=status.HTTP_200_OK)
    
    @require_admin
    @require_admin
    def post(self, request):
        """Create new user (admin only)"""
        serializer = AdminUserSerializer(data=request.data)
        
        if serializer.is_valid():
            # Check if trying to create admin or super_admin user
            user_type_id = request.data.get('user_type_id')
            if user_type_id:
                try:
                    user_type = UserType.objects.get(pk=user_type_id)
                    # Only super admin can create admin or super_admin users
                    if user_type.type_name in ['admin', 'super_admin'] and not request.user.is_super_admin():
                        return Response(
                            {'error': 'Only super admin can create admin or super_admin users'},
                            status=status.HTTP_403_FORBIDDEN
                        )
                except UserType.DoesNotExist:
                    return Response(
                        {'error': 'Invalid user type'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            user = serializer.save()
            return Response({
                'message': 'User created successfully',
                'user': AdminUserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminUserDetailView(APIView):
    """Admin endpoint to view/update/delete specific user"""
    permission_classes = [IsAuthenticated]
    
    def get_user(self, user_id):
        """Helper to get user by ID"""
        try:
            return CustomUser.objects.select_related('user_type').get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None
    
    @require_admin
    def get(self, request, user_id):
        """Get user by ID (admin only)"""
        user = self.get_user(user_id)
        if not user:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = AdminUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @require_admin
    def put(self, request, user_id):
        """Update user (admin only)"""
        target_user = self.get_user(user_id)
        if not target_user:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check modification permission
        allowed, error_msg = check_user_modification_permission(request.user, target_user)
        if not allowed:
            return Response(
                {'error': error_msg},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check user type change permission if user_type_id is provided
        user_type_id = request.data.get('user_type_id')
        if user_type_id:
            try:
                new_user_type = UserType.objects.get(pk=user_type_id)
                allowed, error_msg = check_user_type_change_permission(
                    request.user, target_user, new_user_type
                )
                if not allowed:
                    return Response(
                        {'error': error_msg},
                        status=status.HTTP_403_FORBIDDEN
                    )
            except UserType.DoesNotExist:
                return Response(
                    {'error': 'Invalid user type'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        serializer = AdminUserSerializer(target_user, data=request.data, partial=True)
        
        if serializer.is_valid():
            try:
                serializer.save()
                return Response({
                    'message': 'User updated successfully',
                    'user': serializer.data
                }, status=status.HTTP_200_OK)
            except PermissionDenied as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @require_admin
    def delete(self, request, user_id):
        """Delete user (admin only)"""
        target_user = self.get_user(user_id)
        if not target_user:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check modification permission
        allowed, error_msg = check_user_modification_permission(request.user, target_user)
        if not allowed:
            return Response(
                {'error': error_msg},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            target_user.delete()
            return Response(
                {'message': 'User deleted successfully'},
                status=status.HTTP_200_OK
            )
        except PermissionDenied as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN
            )


class ChangeUserTypeView(APIView):
    """Admin endpoint to change user type"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def patch(self, request, user_id):
        """Change user type (admin/super_admin only)"""
        try:
            target_user = CustomUser.objects.select_related('user_type').get(pk=user_id)
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = ChangeUserTypeSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user_type_id = serializer.validated_data['user_type_id']
        new_user_type = UserType.objects.get(pk=user_type_id)
        
        # Check permission to change user type
        allowed, error_msg = check_user_type_change_permission(
            request.user, target_user, new_user_type
        )
        if not allowed:
            return Response(
                {'error': error_msg},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            target_user.user_type = new_user_type
            target_user.save()
            
            return Response({
                'message': 'User type changed successfully',
                'user': AdminUserSerializer(target_user).data
            }, status=status.HTTP_200_OK)
        except PermissionDenied as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN
            )


class UserTypeListView(APIView):
    """Admin endpoint to list user types"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request):
        """List all user types (admin only)"""
        user_types = UserType.objects.all().order_by('type_name')
        serializer = UserTypeSerializer(user_types, many=True)
        return Response({
            'count': user_types.count(),
            'user_types': serializer.data
        }, status=status.HTTP_200_OK)


# New password reset flow: User requests password reset from super admin
class PasswordResetRequestView(APIView):
    """User submits password reset request that goes to super admin"""
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        reason = serializer.validated_data.get('reason', '')
        
        # In a real application, you would:
        # 1. Create a password reset request record in the database
        # 2. Send notification to super admin (email, dashboard notification, etc.)
        # 3. Super admin reviews and approves/sets temporary password
        
        # For now, we'll just log it
        print(f"\n{'='*60}")
        print(f"PASSWORD RESET REQUEST")
        print(f"Email: {email}")
        print(f"Reason: {reason}")
        print(f"Status: Pending Super Admin Review")
        print(f"{'='*60}\n")
        
        return Response({
            'message': 'Password reset request submitted successfully. Super admin will review and provide a temporary password.'
        }, status=status.HTTP_200_OK)


class SuperAdminPasswordResetView(APIView):
    """Super admin endpoint to set temporary password for user"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def post(self, request):
        serializer = SuperAdminPasswordResetSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user_id = serializer.validated_data['user_id']
        temporary_password = serializer.validated_data['temporary_password']
        
        try:
            user = CustomUser.objects.get(pk=user_id)
            
            # Set temporary password
            user.set_password(temporary_password)
            user.save()
            
            # In a real application, you would:
            # 1. Send email to user with temporary password
            # 2. Mark the password as temporary (requiring change on next login)
            # 3. Log this admin action for audit
            
            print(f"\n{'='*60}")
            print(f"TEMPORARY PASSWORD SET BY SUPER ADMIN")
            print(f"User: {user.email}")
            print(f"Temporary Password: {temporary_password}")
            print(f"Admin: {request.user.email}")
            print(f"NOTE: User should change this password after logging in")
            print(f"{'='*60}\n")
            
            return Response({
                'message': f'Temporary password set successfully for {user.email}',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name
                },
                'temporary_password': temporary_password,
                'note': 'User should change this password after logging in'
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except PermissionDenied as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN
            )


# ============================================
# Page-Based Permission System Views
# ============================================

# Job Role Management Views
class JobRoleListCreateView(APIView):
    """List all job roles or create new job role (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def get(self, request):
        """List all job roles"""
        job_roles = JobRole.objects.all()
        serializer = JobRoleListSerializer(job_roles, many=True)
        return Response({'job_roles': serializer.data}, status=status.HTTP_200_OK)
    
    @require_super_admin
    def post(self, request):
        """Create new job role"""
        serializer = JobRoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobRolePageManagementView(APIView):
    """Get, update, or delete a job role (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def get(self, request, pk):
        """Get job role with linked pages"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            serializer = JobRoleDetailSerializer(job_role)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_super_admin
    def put(self, request, pk):
        """Update job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            serializer = JobRoleSerializer(job_role, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_super_admin
    def delete(self, request, pk):
        """Delete job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            job_role.delete()
            return Response({'message': 'Job role deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({'error': str(e.message)}, status=status.HTTP_400_BAD_REQUEST)


class JobRolePagesView(APIView):
    """Link pages to job role or unlink a page (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def post(self, request, pk):
        """Link pages to job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            serializer = LinkPagesToJobRoleSerializer(data=request.data)
            
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            page_ids = serializer.validated_data['page_ids']
            pages = Page.objects.filter(id__in=page_ids)
            
            with transaction.atomic():
                for page in pages:
                    JobRolePage.objects.get_or_create(
                        job_role=job_role,
                        page=page
                    )
            
            return Response({
                'message': f'Successfully linked {len(pages)} page(s) to job role'
            }, status=status.HTTP_200_OK)
            
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)


class JobRolePageDetailView(APIView):
    """Unlink a specific page from job role (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def delete(self, request, pk, page_id):
        """Unlink page from job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            page = Page.objects.get(pk=page_id)
            
            job_role_page = JobRolePage.objects.filter(
                job_role=job_role,
                page=page
            ).first()
            
            if not job_role_page:
                return Response({
                    'error': f"Page '{page.name}' is not linked to job role '{job_role.name}'"
                }, status=status.HTTP_404_NOT_FOUND)
            
            job_role_page.delete()
            return Response({
                'message': f"Page '{page.name}' unlinked from job role '{job_role.name}'"
            }, status=status.HTTP_204_NO_CONTENT)
            
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)


# Page Management Views
class PageListCreateView(APIView):
    """List all pages or create new page (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def get(self, request):
        """List all pages"""
        pages = Page.objects.all()
        serializer = PageListSerializer(pages, many=True)
        return Response({'pages': serializer.data}, status=status.HTTP_200_OK)
    
    @require_super_admin
    def post(self, request):
        """Create new page"""
        serializer = PageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PageDetailView(APIView):
    """Get, update, or delete a page (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def get(self, request, pk):
        """Get page with actions"""
        try:
            page = Page.objects.prefetch_related('actions').get(pk=pk)
            serializer = PageSerializer(page)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_super_admin
    def put(self, request, pk):
        """Update page"""
        try:
            page = Page.objects.get(pk=pk)
            serializer = PageSerializer(page, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_super_admin
    def delete(self, request, pk):
        """Delete page"""
        try:
            page = Page.objects.get(pk=pk)
            page.delete()
            return Response({'message': 'Page deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({'error': str(e.message)}, status=status.HTTP_400_BAD_REQUEST)


# Page Action Management Views
class PageActionListCreateView(APIView):
    """List all actions for a page or create new action (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def get(self, request, page_id):
        """List all actions for a page"""
        try:
            page = Page.objects.get(pk=page_id)
            actions = page.actions.all()
            serializer = PageActionSerializer(actions, many=True)
            return Response({'actions': serializer.data}, status=status.HTTP_200_OK)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_super_admin
    def post(self, request, page_id):
        """Create action for page"""
        try:
            page = Page.objects.get(pk=page_id)
            data = request.data.copy()
            data['page'] = page.id
            
            serializer = PageActionSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)


class PageActionDetailView(APIView):
    """Update or delete a page action (Super Admin only)"""
    permission_classes = [IsAuthenticated]
    
    @require_super_admin
    def put(self, request, page_id, action_id):
        """Update action"""
        try:
            page = Page.objects.get(pk=page_id)
            action = PageAction.objects.get(pk=action_id, page=page)
            
            serializer = PageActionSerializer(action, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)
        except PageAction.DoesNotExist:
            return Response({'error': 'Action not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_super_admin
    def delete(self, request, page_id, action_id):
        """Delete action"""
        try:
            page = Page.objects.get(pk=page_id)
            action = PageAction.objects.get(pk=action_id, page=page)
            action.delete()
            return Response({'message': 'Action deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Page.DoesNotExist:
            return Response({'error': 'Page not found'}, status=status.HTTP_404_NOT_FOUND)
        except PageAction.DoesNotExist:
            return Response({'error': 'Action not found'}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({'error': str(e.message)}, status=status.HTTP_400_BAD_REQUEST)


# User Permission Management Views
class UserPermissionsView(APIView):
    """Get user's effective page-based permissions"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id):
        """Get user's effective permissions"""
        # Check permission: user can view own permissions, or admin/super_admin can view any user
        if request.user.id != user_id and not request.user.is_admin():
            return Response({
                'error': 'You do not have permission to view this user\'s permissions'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = CustomUser.objects.get(pk=user_id)
            permissions = get_user_page_permissions(user)
            return Response(permissions, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UserDeniedActionsView(APIView):
    """Get only denied actions for user"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id):
        """Get user's denied actions"""
        # Check permission
        if request.user.id != user_id and not request.user.is_admin():
            return Response({
                'error': 'You do not have permission to view this user\'s denied actions'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = CustomUser.objects.get(pk=user_id)
            denied_actions = get_user_denied_actions(user)
            return Response(denied_actions, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UserDenyActionView(APIView):
    """Deny specific action for user"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def post(self, request, user_id):
        """Deny action for user"""
        try:
            user = CustomUser.objects.get(pk=user_id)
            
            # Cannot modify super admin
            if user.is_super_admin():
                return Response({
                    'error': 'Cannot modify permissions for super admin'
                }, status=status.HTTP_403_FORBIDDEN)
            
            serializer = DenyActionSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            # Get the page action
            if 'page_action_id' in serializer.validated_data:
                page_action = PageAction.objects.get(id=serializer.validated_data['page_action_id'])
            else:
                page = Page.objects.get(name=serializer.validated_data['page_name'])
                page_action = PageAction.objects.get(
                    page=page,
                    name=serializer.validated_data['action_name']
                )
            
            # Create denial (or get existing)
            denial, created = UserActionDenial.objects.get_or_create(
                user=user,
                page_action=page_action
            )
            
            if created:
                return Response({
                    'success': True,
                    'denial_id': denial.id,
                    'message': f"Action '{page_action.name}' on page '{page_action.page.name}' denied for user"
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': True,
                    'denial_id': denial.id,
                    'message': 'Action already denied for user'
                }, status=status.HTTP_200_OK)
                
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except (Page.DoesNotExist, PageAction.DoesNotExist) as e:
            return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)


class UserRemoveDenialView(APIView):
    """Remove denial (restore access)"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def delete(self, request, user_id, denial_id):
        """Remove action denial"""
        try:
            user = CustomUser.objects.get(pk=user_id)
            denial = UserActionDenial.objects.get(pk=denial_id, user=user)
            denial.delete()
            return Response({
                'success': True,
                'message': 'Action denial removed, user now has access'
            }, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except UserActionDenial.DoesNotExist:
            return Response({'error': 'Denial not found'}, status=status.HTTP_404_NOT_FOUND)


class UserBulkDenyActionsView(APIView):
    """Deny multiple actions at once"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def post(self, request, user_id):
        """Deny multiple actions for user"""
        try:
            user = CustomUser.objects.get(pk=user_id)
            
            if user.is_super_admin():
                return Response({
                    'error': 'Cannot modify permissions for super admin'
                }, status=status.HTTP_403_FORBIDDEN)
            
            serializer = BulkDenyActionsSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            page_action_ids = serializer.validated_data['page_action_ids']
            denial_ids = []
            
            with transaction.atomic():
                for action_id in page_action_ids:
                    denial, _ = UserActionDenial.objects.get_or_create(
                        user=user,
                        page_action_id=action_id
                    )
                    denial_ids.append(denial.id)
            
            return Response({
                'success': True,
                'denied_count': len(denial_ids),
                'denial_ids': denial_ids
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UserBulkRemoveDenialsView(APIView):
    """Remove multiple denials"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def delete(self, request, user_id):
        """Remove multiple action denials"""
        try:
            user = CustomUser.objects.get(pk=user_id)
            serializer = BulkRemoveDenialsSerializer(data=request.data)
            
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            denial_ids = serializer.validated_data['denial_ids']
            
            with transaction.atomic():
                deleted_count = UserActionDenial.objects.filter(
                    id__in=denial_ids,
                    user=user
                ).delete()[0]
            
            return Response({
                'success': True,
                'removed_count': deleted_count
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


# User Job Role Assignment Views
class UserJobRoleView(APIView):
    """Assign/change or remove user's job role"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def patch(self, request, user_id):
        """Assign/change user's job role"""
        try:
            user = CustomUser.objects.get(pk=user_id)
            
            if user.is_super_admin():
                return Response({
                    'error': 'Cannot modify job role for super admin'
                }, status=status.HTTP_403_FORBIDDEN)
            
            serializer = AssignJobRoleSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            job_role = JobRole.objects.get(id=serializer.validated_data['job_role_id'])
            clear_previous = serializer.validated_data.get('clear_previous_denials', False)
            denied_action_ids = serializer.validated_data.get('denied_action_ids', [])
            
            with transaction.atomic():
                # Assign job role
                user.job_role = job_role
                user.save()
                
                # Clear previous denials if requested
                if clear_previous:
                    UserActionDenial.objects.filter(user=user).delete()
                
                # Add new denials if provided
                if denied_action_ids:
                    for action_id in denied_action_ids:
                        UserActionDenial.objects.get_or_create(
                            user=user,
                            page_action_id=action_id
                        )
            
            message = f"Job role '{job_role.name}' assigned"
            if denied_action_ids:
                message += f" with {len(denied_action_ids)} action denial(s)"
            
            return Response({
                'success': True,
                'message': message
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_admin
    def delete(self, request, user_id):
        """Remove user's job role"""
        try:
            user = CustomUser.objects.get(pk=user_id)
            
            if user.is_super_admin():
                return Response({
                    'error': 'Cannot modify job role for super admin'
                }, status=status.HTTP_403_FORBIDDEN)
            
            with transaction.atomic():
                user.job_role = None
                user.save()
                # Clear all denials since user has no job role
                UserActionDenial.objects.filter(user=user).delete()
            
            return Response({
                'success': True,
                'message': 'Job role removed, all denials cleared'
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


# Permission Check Views
class CheckPermissionView(APIView):
    """Check if current user can perform an action"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Check single permission"""
        serializer = CheckPermissionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        page_name = serializer.validated_data['page_name']
        action_name = serializer.validated_data['action_name']
        
        allowed, reason = user_can_perform_action(request.user, page_name, action_name)
        
        if allowed:
            return Response({'allowed': True}, status=status.HTTP_200_OK)
        else:
            return Response({
                'allowed': False,
                'reason': reason
            }, status=status.HTTP_200_OK)


class BulkCheckPermissionsView(APIView):
    """Check multiple permissions at once"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Check multiple permissions"""
        serializer = BulkCheckPermissionsSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        checks = serializer.validated_data['checks']
        results = []
        
        for check in checks:
            page_name = check['page_name']
            action_name = check['action_name']
            allowed, _ = user_can_perform_action(request.user, page_name, action_name)
            
            results.append({
                'page': page_name,
                'action': action_name,
                'allowed': allowed
            })
        
        return Response({'results': results}, status=status.HTTP_200_OK)


# User's Own Permissions Views
class MyPermissionsView(APIView):
    """Get current user's permissions"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get current user's page permissions"""
        permissions = get_user_page_permissions(request.user)
        
        # Remove denied actions from the response for cleaner output
        if 'pages' in permissions:
            for page in permissions['pages']:
                page['actions'] = [
                    action for action in page['actions']
                    if action['allowed']
                ]
        
        return Response(permissions, status=status.HTTP_200_OK)


class MyPagesView(APIView):
    """Get list of pages current user can access (simplified)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get list of accessible pages"""
        pages = get_user_accessible_pages(request.user)
        return Response({'pages': pages}, status=status.HTTP_200_OK)
