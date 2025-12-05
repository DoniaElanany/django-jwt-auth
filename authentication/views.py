from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.core.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from .models import CustomUser, UserType, JobRole, DutyRole, Resource, DutyRolePermission, UserPermissionOverride
from .serializers import (
    UserRegistrationSerializer,
    UserProfileSerializer,
    AdminUserSerializer,
    ChangeUserTypeSerializer,
    UserTypeSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    SuperAdminPasswordResetSerializer,
    JobRoleSerializer,
    DutyRoleSerializer,
    ResourceSerializer,
    DutyRolePermissionSerializer,
    UserPermissionOverrideSerializer,
    UserPermissionListSerializer
)
from .permissions import (
    require_authentication,
    require_admin,
    require_super_admin,
    check_user_modification_permission,
    check_user_type_change_permission
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


# ========================
# Permission System Views
# ========================

from .permission_utils import get_user_permissions


class JobRoleListView(APIView):
    """List all job roles or create a new one"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request):
        """List all job roles"""
        job_roles = JobRole.objects.all()
        serializer = JobRoleSerializer(job_roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @require_admin
    def post(self, request):
        """Create a new job role"""
        serializer = JobRoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobRoleDetailView(APIView):
    """Retrieve, update, or delete a job role"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request, pk):
        """Get job role details"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            serializer = JobRoleSerializer(job_role)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_admin
    def put(self, request, pk):
        """Update job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            serializer = JobRoleSerializer(job_role, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_admin
    def delete(self, request, pk):
        """Delete job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            job_role.delete()
            return Response({'message': 'Job role deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)


class JobRoleDutyRolesView(APIView):
    """List duty roles for a job role"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request, pk):
        """List all duty roles for a job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            duty_roles = job_role.duty_roles.all()
            serializer = DutyRoleSerializer(duty_roles, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)


class JobRoleUsersView(APIView):
    """List users with a specific job role"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request, pk):
        """List all users with this job role"""
        try:
            job_role = JobRole.objects.get(pk=pk)
            users = CustomUser.objects.filter(job_role=job_role)
            serializer = UserProfileSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)


class AssignDutyRoleView(APIView):
    """Assign a duty role to a job role"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def post(self, request, job_role_pk):
        """Assign duty role to job role"""
        try:
            job_role = JobRole.objects.get(pk=job_role_pk)
            duty_role_id = request.data.get('duty_role_id')
            
            if not duty_role_id:
                return Response({'error': 'duty_role_id is required'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                duty_role = DutyRole.objects.get(pk=duty_role_id)
                job_role.duty_roles.add(duty_role)
                return Response({'message': 'Duty role assigned successfully'}, status=status.HTTP_200_OK)
            except DutyRole.DoesNotExist:
                return Response({'error': 'Duty role not found'}, status=status.HTTP_404_NOT_FOUND)
                
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)


class RemoveDutyRoleView(APIView):
    """Remove a duty role from a job role"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def delete(self, request, job_role_pk, duty_role_pk):
        """Remove duty role from job role"""
        try:
            job_role = JobRole.objects.get(pk=job_role_pk)
            try:
                duty_role = DutyRole.objects.get(pk=duty_role_pk)
                job_role.duty_roles.remove(duty_role)
                return Response({'message': 'Duty role removed successfully'}, status=status.HTTP_200_OK)
            except DutyRole.DoesNotExist:
                return Response({'error': 'Duty role not found'}, status=status.HTTP_404_NOT_FOUND)
        except JobRole.DoesNotExist:
            return Response({'error': 'Job role not found'}, status=status.HTTP_404_NOT_FOUND)


class DutyRoleListView(APIView):
    """List all duty roles or create a new one"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request):
        """List all duty roles"""
        duty_roles = DutyRole.objects.all()
        serializer = DutyRoleSerializer(duty_roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @require_admin
    def post(self, request):
        """Create a new duty role"""
        serializer = DutyRoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DutyRoleDetailView(APIView):
    """Retrieve, update, or delete a duty role"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request, pk):
        """Get duty role details"""
        try:
            duty_role = DutyRole.objects.get(pk=pk)
            serializer = DutyRoleSerializer(duty_role)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except DutyRole.DoesNotExist:
            return Response({'error': 'Duty role not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_admin
    def put(self, request, pk):
        """Update duty role"""
        try:
            duty_role = DutyRole.objects.get(pk=pk)
            serializer = DutyRoleSerializer(duty_role, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except DutyRole.DoesNotExist:
            return Response({'error': 'Duty role not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_admin
    def delete(self, request, pk):
        """Delete duty role"""
        try:
            duty_role = DutyRole.objects.get(pk=pk)
            duty_role.delete()
            return Response({'message': 'Duty role deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except DutyRole.DoesNotExist:
            return Response({'error': 'Duty role not found'}, status=status.HTTP_404_NOT_FOUND)


class ResourceListView(APIView):
    """List all resources or create a new one"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request):
        """List all resources"""
        resources = Resource.objects.all()
        serializer = ResourceSerializer(resources, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @require_admin
    def post(self, request):
        """Create a new resource"""
        serializer = ResourceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResourceDetailView(APIView):
    """Retrieve or delete a resource"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request, pk):
        """Get resource details"""
        try:
            resource = Resource.objects.get(pk=pk)
            serializer = ResourceSerializer(resource)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Resource.DoesNotExist:
            return Response({'error': 'Resource not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @require_admin
    def delete(self, request, pk):
        """Delete resource"""
        try:
            resource = Resource.objects.get(pk=pk)
            resource.delete()
            return Response({'message': 'Resource deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Resource.DoesNotExist:
            return Response({'error': 'Resource not found'}, status=status.HTTP_404_NOT_FOUND)


class DutyRolePermissionView(APIView):
    """Set or update permissions for a duty role on a resource"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def post(self, request):
        """Set duty role permission"""
        serializer = DutyRolePermissionSerializer(data=request.data)
        if serializer.is_valid():
            # Check if permission already exists
            duty_role = serializer.validated_data['duty_role']
            resource = serializer.validated_data['resource']
            
            try:
                existing = DutyRolePermission.objects.get(duty_role=duty_role, resource=resource)
                # Update existing
                serializer = DutyRolePermissionSerializer(existing, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
            except DutyRolePermission.DoesNotExist:
                # Create new
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @require_admin
    def get(self, request):
        """Get permissions for a duty role on a resource"""
        duty_role_id = request.query_params.get('duty_role_id')
        resource_id = request.query_params.get('resource_id')
        
        if not duty_role_id or not resource_id:
            return Response(
                {'error': 'duty_role_id and resource_id are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            permission = DutyRolePermission.objects.get(
                duty_role_id=duty_role_id,
                resource_id=resource_id
            )
            serializer = DutyRolePermissionSerializer(permission)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except DutyRolePermission.DoesNotExist:
            return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)


class DutyRolePermissionListView(APIView):
    """List all duty role permissions"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request):
        """List all duty role permissions with optional filtering"""
        permissions = DutyRolePermission.objects.all()
        
        # Optional filters
        duty_role_id = request.query_params.get('duty_role_id')
        resource_id = request.query_params.get('resource_id')
        
        if duty_role_id:
            permissions = permissions.filter(duty_role_id=duty_role_id)
        if resource_id:
            permissions = permissions.filter(resource_id=resource_id)
        
        serializer = DutyRolePermissionSerializer(permissions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DutyRolePermissionDeleteView(APIView):
    """Remove a duty role permission"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def delete(self, request, pk):
        """Delete duty role permission"""
        try:
            permission = DutyRolePermission.objects.get(pk=pk)
            permission.delete()
            return Response({'message': 'Permission deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except DutyRolePermission.DoesNotExist:
            return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)


class UserPermissionOverrideView(APIView):
    """Set or update permission override for a user"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def post(self, request):
        """Set user permission override"""
        serializer = UserPermissionOverrideSerializer(data=request.data)
        if serializer.is_valid():
            # Check if override already exists
            user = serializer.validated_data['user']
            duty_role = serializer.validated_data['duty_role']
            resource = serializer.validated_data['resource']
            
            try:
                existing = UserPermissionOverride.objects.get(
                    user=user,
                    duty_role=duty_role,
                    resource=resource
                )
                # Update existing
                serializer = UserPermissionOverrideSerializer(existing, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
            except UserPermissionOverride.DoesNotExist:
                # Create new
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPermissionOverrideListView(APIView):
    """List user permission overrides"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def get(self, request):
        """List all overrides or get overrides for a specific user"""
        user_id = request.query_params.get('user_id')
        
        if user_id:
            overrides = UserPermissionOverride.objects.filter(user_id=user_id)
        else:
            overrides = UserPermissionOverride.objects.all()
        
        serializer = UserPermissionOverrideSerializer(overrides, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserPermissionOverrideDeleteView(APIView):
    """Remove a user permission override"""
    permission_classes = [IsAuthenticated]
    
    @require_admin
    def delete(self, request, pk):
        """Delete user permission override"""
        try:
            override = UserPermissionOverride.objects.get(pk=pk)
            override.delete()
            return Response({'message': 'Override deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except UserPermissionOverride.DoesNotExist:
            return Response({'error': 'Override not found'}, status=status.HTTP_404_NOT_FOUND)


class UserEffectivePermissionsView(APIView):
    """Get effective permissions for a user (including overrides)"""
    permission_classes = [IsAuthenticated]
    
    @require_authentication
    def get(self, request):
        """Get effective permissions for the authenticated user"""
        user = request.user
        resource_name = request.query_params.get('resource')
        
        permissions = get_user_permissions(user, resource_name)
        
        if permissions == {'_admin': 'full_access'}:
            return Response({
                'message': 'Admin/Super Admin has full access to all resources'
            }, status=status.HTTP_200_OK)
        
        # Format permissions for response
        permissions_list = []
        for resource, perms in permissions.items():
            permissions_list.append({
                'resource': resource,
                **perms
            })
        
        return Response(permissions_list, status=status.HTTP_200_OK)
