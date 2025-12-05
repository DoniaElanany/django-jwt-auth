from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.validators import EmailValidator, RegexValidator
from .models import CustomUser, UserType, JobRole,Page, PageAction, JobRolePage, UserActionDenial
import re


class UserTypeSerializer(serializers.ModelSerializer):
    """Serializer for UserType model"""
    class Meta:
        model = UserType
        fields = ['id', 'type_name', 'description']
        read_only_fields = ['id']


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration (public endpoint)"""
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = CustomUser
        fields = ['email', 'name', 'phone_number', 'password', 'confirm_password']
    
    def validate_email(self, value):
        """Validate email format"""
        validator = EmailValidator(message="Enter a valid email address")
        validator(value)
        
        # Check if email already exists
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already registered")
        
        return value
    
    def validate_phone_number(self, value):
        """Validate phone number format (Egyptian or international)"""
        # Egyptian phone format: +20XXXXXXXXXX or 01XXXXXXXXX or international format
        phone_regex = RegexValidator(
            regex=r'^(\+?\d{1,3})?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}$',
            message="Enter a valid phone number"
        )
        phone_regex(value)
        return value
    
    def validate_password(self, value):
        """Validate password strength"""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        # Use Django's built-in password validators
        validate_password(value)
        return value
    
    def validate(self, attrs):
        """Validate that passwords match"""
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})
        return attrs
    
    def create(self, validated_data):
        """Create new user with user type"""
        validated_data.pop('confirm_password')
        
        # Get or create 'user' type
        user_type, _ = UserType.objects.get_or_create(
            type_name='user',
            defaults={'description': 'Regular user with basic permissions'}
        )
        
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            phone_number=validated_data['phone_number'],
            password=validated_data['password']
        )
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile (users updating their own profile)"""
    user_type = serializers.CharField(source='user_type.type_name', read_only=True)
    job_role_name = serializers.CharField(source='job_role.name', read_only=True)
    password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'name', 'phone_number', 'user_type', 'job_role_name', 'password']
        read_only_fields = ['id', 'email', 'user_type', 'job_role_name']
    
    def validate_phone_number(self, value):
        """Validate phone number format"""
        phone_regex = RegexValidator(
            regex=r'^(\+?\d{1,3})?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}$',
            message="Enter a valid phone number"
        )
        phone_regex(value)
        return value
    
    def validate_password(self, value):
        """Validate password strength"""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        validate_password(value)
        return value
    
    def update(self, instance, validated_data):
        """Update user profile"""
        password = validated_data.pop('password', None)
        
        # Update fields
        instance.name = validated_data.get('name', instance.name)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        
        # Update password if provided
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance


class AdminUserSerializer(serializers.ModelSerializer):
    """Serializer for admin operations (full access to user fields)"""
    user_type = UserTypeSerializer(read_only=True)
    user_type_id = serializers.IntegerField(write_only=True, required=False)
    job_role_id = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    job_role_name = serializers.CharField(source='job_role.name', read_only=True)
    password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'name', 'phone_number', 'user_type', 'user_type_id', 
            'job_role_id', 'job_role_name', 'password'
        ]
        read_only_fields = ['id']
    
    def validate_email(self, value):
        """Validate email format"""
        validator = EmailValidator(message="Enter a valid email address")
        validator(value)
        
        # Check if email already exists (exclude current user during update)
        instance = getattr(self, 'instance', None)
        if instance:
            if CustomUser.objects.exclude(pk=instance.pk).filter(email=value).exists():
                raise serializers.ValidationError("Email already registered")
        else:
            if CustomUser.objects.filter(email=value).exists():
                raise serializers.ValidationError("Email already registered")
        
        return value
    
    def validate_phone_number(self, value):
        """Validate phone number format"""
        phone_regex = RegexValidator(
            regex=r'^(\+?\d{1,3})?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}$',
            message="Enter a valid phone number"
        )
        phone_regex(value)
        return value
    
    def validate_password(self, value):
        """Validate password strength"""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        validate_password(value)
        return value
    
    def validate_user_type_id(self, value):
        """Validate that user_type_id exists"""
        try:
            UserType.objects.get(pk=value)
        except UserType.DoesNotExist:
            raise serializers.ValidationError("Invalid user type")
        return value
    
    def create(self, validated_data):
        """Create new user (admin operation)"""
        password = validated_data.pop('password', None)
        user_type_id = validated_data.pop('user_type_id', None)
        
        # Get user type or default to 'user'
        if user_type_id:
            user_type = UserType.objects.get(pk=user_type_id)
        else:
            user_type, _ = UserType.objects.get_or_create(
                type_name='user',
                defaults={'description': 'Regular user with basic permissions'}
            )
        
        user = CustomUser.objects.create(
            email=validated_data['email'],
            name=validated_data['name'],
            phone_number=validated_data['phone_number'],
            user_type=user_type
        )
        
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        
        user.save()
        return user
    
    def update(self, instance, validated_data):
        """Update user (admin operation)"""
        password = validated_data.pop('password', None)
        user_type_id = validated_data.pop('user_type_id', None)
        job_role_id = validated_data.pop('job_role_id', None)
        
        # Update basic fields
        instance.name = validated_data.get('name', instance.name)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.email = validated_data.get('email', instance.email)
        
        # Update user type if provided (will be validated by model's save method)
        if user_type_id:
            user_type = UserType.objects.get(pk=user_type_id)
            instance.user_type = user_type
        
        # Update job role if provided
        if job_role_id is not None:
            if job_role_id == 0:  # Allow explicitly removing job role
                instance.job_role = None
            else:
                try:
                    job_role = JobRole.objects.get(pk=job_role_id)
                    instance.job_role = job_role
                except JobRole.DoesNotExist:
                    pass  # Silently ignore invalid job role ID
        
        # Update password if provided
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance


class ChangeUserTypeSerializer(serializers.Serializer):
    """Serializer for changing user type"""
    user_type_id = serializers.IntegerField(required=True)
    
    def validate_user_type_id(self, value):
        """Validate that user_type_id exists"""
        try:
            UserType.objects.get(pk=value)
        except UserType.DoesNotExist:
            raise serializers.ValidationError("Invalid user type")
        return value


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password when user is logged in"""
    old_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    confirm_new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    def validate_old_password(self, value):
        """Verify the old password is correct"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value
    
    def validate_new_password(self, value):
        """Validate new password strength"""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        # Use Django's built-in password validators
        validate_password(value)
        return value
    
    def validate(self, attrs):
        """Validate that new passwords match and is different from old password"""
        if attrs['new_password'] != attrs['confirm_new_password']:
            raise serializers.ValidationError({"confirm_new_password": "New passwords do not match"})
        
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError({"new_password": "New password must be different from current password"})
        
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for requesting password reset from super admin"""
    email = serializers.EmailField(required=True)
    reason = serializers.CharField(required=False, allow_blank=True, max_length=500)
    
    def validate_email(self, value):
        """Validate that email exists"""
        if not CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("No account found with this email")
        return value


class SuperAdminPasswordResetSerializer(serializers.Serializer):
    """Serializer for super admin to reset user password"""
    user_id = serializers.IntegerField(required=True)
    temporary_password = serializers.CharField(required=True, min_length=8)
    
    def validate_user_id(self, value):
        """Validate that user exists and is not super admin"""
        try:
            user = CustomUser.objects.get(pk=value)
            if user.is_super_admin():
                raise serializers.ValidationError("Cannot reset super admin password")
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found")
        return value


# ============================================
# Page-Based Permission System Serializers
# ============================================

class JobRoleSerializer(serializers.ModelSerializer):
    """Serializer for JobRole model""" 
    class Meta:
        model = JobRole
        fields = ['id', 'name', 'description', 'duty_roles', 'duty_role_ids']
        read_only_fields = ['id']
    
    def validate_name(self, value):
        """Validate job role name is unique"""
        if self.instance is None:  # Creating new
            if JobRole.objects.filter(name=value).exists():
                raise serializers.ValidationError("Job role with this name already exists")
        else:  # Updating existing
            if JobRole.objects.filter(name=value).exclude(pk=self.instance.pk).exists():
                raise serializers.ValidationError("Job role with this name already exists")
        return value
    
    def create(self, validated_data):
        """Create job role and assign duty roles"""
        job_role = JobRole.objects.create(**validated_data)
        return job_role
    
    def update(self, instance, validated_data):
        """Update job role and duty roles"""        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        return instance
    
class PageActionSerializer(serializers.ModelSerializer):
    """Serializer for PageAction model"""
    page_name = serializers.CharField(source='page.name', read_only=True)
    
    class Meta:
        model = PageAction
        fields = ['id', 'page', 'page_name', 'name', 'display_name', 'description', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate(self, data):
        """Validate that action name is unique within the page"""
        page = data.get('page')
        name = data.get('name')
        
        if page and name:
            query = PageAction.objects.filter(page=page, name=name)
            if self.instance:
                query = query.exclude(pk=self.instance.pk)
            
            if query.exists():
                raise serializers.ValidationError({
                    'name': f"Action '{name}' already exists for page '{page.name}'"
                })
        
        return data


class PageSerializer(serializers.ModelSerializer):
    """Serializer for Page model"""
    actions = PageActionSerializer(many=True, read_only=True)
    action_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Page
        fields = ['id', 'name', 'display_name', 'description', 'route', 'actions', 'action_count', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_action_count(self, obj):
        return obj.actions.count()


class PageListSerializer(serializers.ModelSerializer):
    """Simplified serializer for listing pages"""
    action_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Page
        fields = ['id', 'name', 'display_name', 'route', 'action_count']
    
    def get_action_count(self, obj):
        return obj.actions.count()


class JobRolePageSerializer(serializers.ModelSerializer):
    """Serializer for JobRolePage junction model"""
    page_name = serializers.CharField(source='page.name', read_only=True)
    page_display_name = serializers.CharField(source='page.display_name', read_only=True)
    
    class Meta:
        model = JobRolePage
        fields = ['id', 'job_role', 'page', 'page_name', 'page_display_name', 'created_at']
        read_only_fields = ['id', 'created_at']


class JobRoleDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for JobRole with linked pages"""
    pages = serializers.SerializerMethodField()
    user_count = serializers.SerializerMethodField()
    
    class Meta:
        model = JobRole
        fields = ['id', 'name', 'description', 'pages', 'user_count', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_pages(self, obj):
        job_role_pages = obj.job_role_pages.select_related('page').all()
        return [{
            'id': jrp.page.id,
            'name': jrp.page.name,
            'display_name': jrp.page.display_name,
            'route': jrp.page.route
        } for jrp in job_role_pages]
    
    def get_user_count(self, obj):
        return obj.users.count()


class JobRoleListSerializer(serializers.ModelSerializer):
    """Simplified serializer for listing job roles"""
    user_count = serializers.SerializerMethodField()
    page_count = serializers.SerializerMethodField()
    
    class Meta:
        model = JobRole
        fields = ['id', 'name', 'description', 'user_count', 'page_count']
    
    def get_user_count(self, obj):
        return obj.users.count()
    
    def get_page_count(self, obj):
        return obj.job_role_pages.count()


class LinkPagesToJobRoleSerializer(serializers.Serializer):
    """Serializer for linking multiple pages to a job role"""
    page_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False
    )
    
    def validate_page_ids(self, value):
        """Validate that all page IDs exist"""
        from .models import Page
        
        existing_ids = set(Page.objects.filter(id__in=value).values_list('id', flat=True))
        invalid_ids = set(value) - existing_ids
        
        if invalid_ids:
            raise serializers.ValidationError(f"Invalid page IDs: {list(invalid_ids)}")
        
        return value


class UserActionDenialSerializer(serializers.ModelSerializer):
    """Serializer for UserActionDenial model"""
    page_name = serializers.CharField(source='page_action.page.name', read_only=True)
    page_display_name = serializers.CharField(source='page_action.page.display_name', read_only=True)
    action_name = serializers.CharField(source='page_action.name', read_only=True)
    action_display_name = serializers.CharField(source='page_action.display_name', read_only=True)
    
    class Meta:
        model = UserActionDenial
        fields = ['id', 'user', 'page_action', 'page_name', 'page_display_name', 
                  'action_name', 'action_display_name', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class DenyActionSerializer(serializers.Serializer):
    """Serializer for denying a specific action for a user"""
    page_action_id = serializers.IntegerField(required=False)
    page_name = serializers.CharField(required=False)
    action_name = serializers.CharField(required=False)
    
    def validate(self, data):
        """Validate that either page_action_id OR (page_name + action_name) is provided"""
        has_action_id = 'page_action_id' in data
        has_names = 'page_name' in data and 'action_name' in data
        
        if not has_action_id and not has_names:
            raise serializers.ValidationError(
                "Either 'page_action_id' or both 'page_name' and 'action_name' must be provided"
            )
        
        if has_action_id and has_names:
            raise serializers.ValidationError(
                "Provide either 'page_action_id' or 'page_name'+'action_name', not both"
            )
        
        # Validate that the page action exists
        if has_action_id:
            from .models import PageAction
            try:
                PageAction.objects.get(id=data['page_action_id'])
            except PageAction.DoesNotExist:
                raise serializers.ValidationError({'page_action_id': 'Page action not found'})
        
        if has_names:
            from .models import PageAction, Page
            try:
                page = Page.objects.get(name=data['page_name'])
                PageAction.objects.get(page=page, name=data['action_name'])
            except Page.DoesNotExist:
                raise serializers.ValidationError({'page_name': f"Page '{data['page_name']}' not found"})
            except PageAction.DoesNotExist:
                raise serializers.ValidationError({
                    'action_name': f"Action '{data['action_name']}' not found on page '{data['page_name']}'"
                })
        
        return data


class BulkDenyActionsSerializer(serializers.Serializer):
    """Serializer for denying multiple actions at once"""
    page_action_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False
    )
    
    def validate_page_action_ids(self, value):
        """Validate that all page action IDs exist"""
        from .models import PageAction
        
        existing_ids = set(PageAction.objects.filter(id__in=value).values_list('id', flat=True))
        invalid_ids = set(value) - existing_ids
        
        if invalid_ids:
            raise serializers.ValidationError(f"Invalid page action IDs: {list(invalid_ids)}")
        
        return value


class BulkRemoveDenialsSerializer(serializers.Serializer):
    """Serializer for removing multiple denials at once"""
    denial_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False
    )


class AssignJobRoleSerializer(serializers.Serializer):
    """Serializer for assigning/changing a user's job role"""
    job_role_id = serializers.IntegerField()
    clear_previous_denials = serializers.BooleanField(default=False)
    denied_action_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        allow_empty=True
    )
    
    def validate_job_role_id(self, value):
        """Validate that job role exists"""
        from .models import JobRole
        try:
            JobRole.objects.get(id=value)
        except JobRole.DoesNotExist:
            raise serializers.ValidationError("Job role not found")
        return value
    
    def validate_denied_action_ids(self, value):
        """Validate that all denied action IDs exist"""
        if value:
            from .models import PageAction
            existing_ids = set(PageAction.objects.filter(id__in=value).values_list('id', flat=True))
            invalid_ids = set(value) - existing_ids
            
            if invalid_ids:
                raise serializers.ValidationError(f"Invalid page action IDs: {list(invalid_ids)}")
        
        return value


class CheckPermissionSerializer(serializers.Serializer):
    """Serializer for checking a single permission"""
    page_name = serializers.CharField()
    action_name = serializers.CharField()


class BulkCheckPermissionsSerializer(serializers.Serializer):
    """Serializer for checking multiple permissions at once"""
    checks = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False
    )
    
    def validate_checks(self, value):
        """Validate that each check has page_name and action_name"""
        for check in value:
            if 'page_name' not in check or 'action_name' not in check:
                raise serializers.ValidationError(
                    "Each check must contain 'page_name' and 'action_name'"
                )
        return value


class UserPermissionResponseSerializer(serializers.Serializer):
    """Serializer for user permission response"""
    user_id = serializers.IntegerField()
    name = serializers.CharField()
    user_type = serializers.CharField()
    job_role = serializers.DictField(allow_null=True)
    pages = serializers.ListField()


class UserDeniedActionsResponseSerializer(serializers.Serializer):
    """Serializer for user denied actions response"""
    user_id = serializers.IntegerField()
    denied_actions = serializers.ListField()


class UserPageListSerializer(serializers.Serializer):
    """Serializer for simplified user page list"""
    name = serializers.CharField()
    display_name = serializers.CharField()
    route = serializers.CharField()

