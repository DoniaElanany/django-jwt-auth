from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.validators import EmailValidator, RegexValidator
from .models import CustomUser, UserType
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
    password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'name', 'phone_number', 'user_type', 'password']
        read_only_fields = ['id', 'email', 'user_type']
    
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
    password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'name', 'phone_number', 'user_type', 'user_type_id', 'password'
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
        
        # Update basic fields
        instance.name = validated_data.get('name', instance.name)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.email = validated_data.get('email', instance.email)
        
        # Update user type if provided (will be validated by model's save method)
        if user_type_id:
            user_type = UserType.objects.get(pk=user_type_id)
            instance.user_type = user_type
        
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
