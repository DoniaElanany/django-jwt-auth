from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import make_password
from django.db import models
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models.signals import pre_delete, pre_save
from django.dispatch import receiver


class UserType(models.Model):
    """User type model with three types: user, admin, and super_admin"""
    type_name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'user_types'
    
    def __str__(self):
        return self.type_name


class JobRole(models.Model):
    """Job role model representing positions in the organization"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'job_roles'
    
    def __str__(self):
        return self.name
    
    def delete(self, *args, **kwargs):
        """Prevent deletion if job role is assigned to users"""
        if self.users.exists():
            raise ValidationError(f"Cannot delete job role '{self.name}' because it is assigned to {self.users.count()} user(s)")
        return super().delete(*args, **kwargs)


class DutyRole(models.Model):
    """Duty role model representing specific responsibilities"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    job_roles = models.ManyToManyField(JobRole, related_name='duty_roles', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'duty_roles'
    
    def __str__(self):
        return self.name
    
    def delete(self, *args, **kwargs):
        """Prevent deletion if duty role has permissions or is linked to job roles"""
        if self.permissions.exists():
            raise ValidationError(f"Cannot delete duty role '{self.name}' because it has {self.permissions.count()} permission(s)")
        if self.job_roles.exists():
            raise ValidationError(f"Cannot delete duty role '{self.name}' because it is linked to {self.job_roles.count()} job role(s)")
        return super().delete(*args, **kwargs)


class Resource(models.Model):
    """Resource model representing system resources that can be accessed"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'resources'
    
    def __str__(self):
        return self.name
    
    def delete(self, *args, **kwargs):
        """Prevent deletion if resource has permissions"""
        if self.duty_role_permissions.exists():
            raise ValidationError(f"Cannot delete resource '{self.name}' because it has {self.duty_role_permissions.count()} permission(s)")
        return super().delete(*args, **kwargs)


class DutyRolePermission(models.Model):
    """Default CRUD permissions for duty roles on resources"""
    duty_role = models.ForeignKey(DutyRole, on_delete=models.CASCADE, related_name='permissions')
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name='duty_role_permissions')
    can_create = models.BooleanField(default=False)
    can_read = models.BooleanField(default=False)
    can_update = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'duty_role_permissions'
        unique_together = ('duty_role', 'resource')
    
    def __str__(self):
        return f"{self.duty_role.name} - {self.resource.name}"


class CustomUserManager(BaseUserManager):
    """Custom user manager for CustomUser model"""
    
    def create_user(self, email, name, phone_number, password=None, user_type=None, **extra_fields):
        """Create and save a regular user"""
        if not email:
            raise ValueError('Email is required')
        if not name:
            raise ValueError('Name is required')
        if not phone_number:
            raise ValueError('Phone number is required')
        
        email = self.normalize_email(email)
        
        # Get or create 'user' type if not provided
        if user_type is None:
            user_type, _ = UserType.objects.get_or_create(
                type_name='user',
                defaults={'description': 'Regular user with basic permissions'}
            )
        
        user = self.model(
            email=email,
            name=name,
            phone_number=phone_number,
            user_type=user_type,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, name, phone_number, password=None, **extra_fields):
        """Create and save a super admin user (for Django admin compatibility)"""
        if not email:
            raise ValueError('Email is required')
        if not name:
            raise ValueError('Name is required')
        if not phone_number:
            raise ValueError('Phone number is required')
        
        email = self.normalize_email(email)
        
        # Get or create 'super_admin' type
        super_admin_type, _ = UserType.objects.get_or_create(
            type_name='super_admin',
            defaults={'description': 'Super administrator with full system access'}
        )
        
        # Create user with super_admin type directly
        user = self.model(
            email=email,
            name=name,
            phone_number=phone_number,
            user_type=super_admin_type,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser):
    """Simplified custom user model with email authentication"""
    email = models.EmailField(unique=True, db_index=True)
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    user_type = models.ForeignKey(UserType, on_delete=models.PROTECT, related_name='users')
    job_role = models.ForeignKey(JobRole, on_delete=models.SET_NULL, null=True, blank=True, related_name='users')
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone_number']
    
    class Meta:
        db_table = 'custom_users'
    
    def __str__(self):
        return f"{self.name} ({self.email})"
    
    def is_super_admin(self):
        """Check if user is super admin"""
        return self.user_type.type_name == 'super_admin'
    
    def is_admin(self):
        """Check if user is admin or super admin"""
        return self.user_type.type_name in ['admin', 'super_admin']
    
    def delete(self, *args, **kwargs):
        """Override delete to prevent deletion of super admin"""
        if self.is_super_admin():
            raise PermissionDenied("Cannot delete the super admin user")
        return super().delete(*args, **kwargs)
    
    def save(self, *args, **kwargs):
        """Override save to protect super admin properties"""
        if self.pk:  # Only for existing users
            try:
                old_user = CustomUser.objects.get(pk=self.pk)
                
                # Prevent changing user_type of super admin
                if old_user.is_super_admin() and old_user.user_type_id != self.user_type_id:
                    raise PermissionDenied("Cannot change user type of super admin")
            except CustomUser.DoesNotExist:
                pass
        
        return super().save(*args, **kwargs)


class UserPermissionOverride(models.Model):
    """User-specific permission overrides"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='permission_overrides')
    duty_role = models.ForeignKey(DutyRole, on_delete=models.CASCADE, related_name='user_overrides')
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name='user_overrides')
    can_create = models.BooleanField(null=True, blank=True)  # NULL = use default, False = explicitly denied, True = explicitly allowed
    can_read = models.BooleanField(null=True, blank=True)
    can_update = models.BooleanField(null=True, blank=True)
    can_delete = models.BooleanField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_permission_overrides'
        unique_together = ('user', 'duty_role', 'resource')
    
    def __str__(self):
        return f"{self.user.email} - {self.duty_role.name} - {self.resource.name}"


# Signals for additional protection
@receiver(pre_delete, sender=CustomUser)
def prevent_super_admin_deletion(sender, instance, **kwargs):
    """Signal to prevent deletion of super admin"""
    if instance.is_super_admin():
        raise PermissionDenied("Cannot delete the super admin user")


@receiver(pre_save, sender=CustomUser)
def prevent_super_admin_modification(sender, instance, **kwargs):
    """Signal to prevent unauthorized modification of super admin"""
    if instance.pk:  # Only for updates
        try:
            old_user = CustomUser.objects.get(pk=instance.pk)
            
            # Prevent changing user_type of super admin
            if old_user.is_super_admin() and old_user.user_type_id != instance.user_type_id:
                raise PermissionDenied("Cannot change user type of super admin")
        except CustomUser.DoesNotExist:
            pass