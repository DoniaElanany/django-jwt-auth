from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.validators import EmailValidator, RegexValidator
from .models import CustomUser, UserType, JobRole, DutyRole, Resource, DutyRolePermission, UserPermissionOverride
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


# ========================
# Permission System Serializers
# ========================

class ResourceSerializer(serializers.ModelSerializer):
    """Serializer for Resource model"""
    class Meta:
        model = Resource
        fields = ['id', 'name', 'description']
        read_only_fields = ['id']
    
    def validate_name(self, value):
        """Validate resource name is unique"""
        if self.instance is None:  # Creating new
            if Resource.objects.filter(name=value).exists():
                raise serializers.ValidationError("Resource with this name already exists")
        else:  # Updating existing
            if Resource.objects.filter(name=value).exclude(pk=self.instance.pk).exists():
                raise serializers.ValidationError("Resource with this name already exists")
        return value


class DutyRoleSerializer(serializers.ModelSerializer):
    """Serializer for DutyRole model"""
    class Meta:
        model = DutyRole
        fields = ['id', 'name', 'description']
        read_only_fields = ['id']
    
    def validate_name(self, value):
        """Validate duty role name is unique"""
        if self.instance is None:  # Creating new
            if DutyRole.objects.filter(name=value).exists():
                raise serializers.ValidationError("Duty role with this name already exists")
        else:  # Updating existing
            if DutyRole.objects.filter(name=value).exclude(pk=self.instance.pk).exists():
                raise serializers.ValidationError("Duty role with this name already exists")
        return value


class JobRoleSerializer(serializers.ModelSerializer):
    """Serializer for JobRole model"""
    duty_roles = DutyRoleSerializer(many=True, read_only=True)
    duty_role_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )
    
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
    
    def validate_duty_role_ids(self, value):
        """Validate duty roles exist"""
        if value:
            for duty_role_id in value:
                if not DutyRole.objects.filter(pk=duty_role_id).exists():
                    raise serializers.ValidationError(f"Duty role with id {duty_role_id} does not exist")
        return value
    
    def create(self, validated_data):
        """Create job role and assign duty roles"""
        duty_role_ids = validated_data.pop('duty_role_ids', [])
        job_role = JobRole.objects.create(**validated_data)
        
        if duty_role_ids:
            duty_roles = DutyRole.objects.filter(pk__in=duty_role_ids)
            job_role.duty_roles.set(duty_roles)
        
        return job_role
    
    def update(self, instance, validated_data):
        """Update job role and duty roles"""
        duty_role_ids = validated_data.pop('duty_role_ids', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        if duty_role_ids is not None:
            duty_roles = DutyRole.objects.filter(pk__in=duty_role_ids)
            instance.duty_roles.set(duty_roles)
        
        return instance


class DutyRolePermissionSerializer(serializers.ModelSerializer):
    """Serializer for DutyRolePermission model"""
    duty_role_name = serializers.CharField(source='duty_role.name', read_only=True)
    resource_name = serializers.CharField(source='resource.name', read_only=True)
    
    class Meta:
        model = DutyRolePermission
        fields = [
            'id', 'duty_role', 'duty_role_name', 'resource', 'resource_name',
            'can_create', 'can_read', 'can_update', 'can_delete'
        ]
        read_only_fields = ['id']
    
    def validate(self, data):
        """Validate unique constraint for duty_role + resource"""
        duty_role = data.get('duty_role')
        resource = data.get('resource')
        
        if self.instance is None:  # Creating new
            if DutyRolePermission.objects.filter(duty_role=duty_role, resource=resource).exists():
                raise serializers.ValidationError("Permission already exists for this duty role and resource")
        else:  # Updating existing
            if DutyRolePermission.objects.filter(
                duty_role=duty_role, 
                resource=resource
            ).exclude(pk=self.instance.pk).exists():
                raise serializers.ValidationError("Permission already exists for this duty role and resource")
        
        return data


class UserPermissionOverrideSerializer(serializers.ModelSerializer):
    """Serializer for UserPermissionOverride model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    duty_role_name = serializers.CharField(source='duty_role.name', read_only=True)
    resource_name = serializers.CharField(source='resource.name', read_only=True)
    
    class Meta:
        model = UserPermissionOverride
        fields = [
            'id', 'user', 'user_email', 'duty_role', 'duty_role_name', 
            'resource', 'resource_name',
            'can_create', 'can_read', 'can_update', 'can_delete'
        ]
        read_only_fields = ['id']
    
    def validate(self, data):
        """Validate unique constraint for user + duty_role + resource"""
        user = data.get('user')
        duty_role = data.get('duty_role')
        resource = data.get('resource')
        
        # Validate user has this duty role through their job role
        if user.job_role and duty_role not in user.job_role.duty_roles.all():
            raise serializers.ValidationError(
                f"User does not have the duty role '{duty_role.name}' in their job role"
            )
        
        if self.instance is None:  # Creating new
            if UserPermissionOverride.objects.filter(
                user=user, 
                duty_role=duty_role, 
                resource=resource
            ).exists():
                raise serializers.ValidationError("Override already exists for this user, duty role, and resource")
        else:  # Updating existing
            if UserPermissionOverride.objects.filter(
                user=user,
                duty_role=duty_role,
                resource=resource
            ).exclude(pk=self.instance.pk).exists():
                raise serializers.ValidationError("Override already exists for this user, duty role, and resource")
        
        return data


class UserPermissionListSerializer(serializers.Serializer):
    """Serializer for listing user permissions (read-only)"""
    resource = serializers.CharField()
    can_create = serializers.BooleanField()
    can_read = serializers.BooleanField()
    can_update = serializers.BooleanField()
    can_delete = serializers.BooleanField()
