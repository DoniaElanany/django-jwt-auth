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


class Page(models.Model):
    """Page model representing functional areas of the system"""
    name = models.CharField(max_length=100, unique=True, db_index=True)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    route = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pages'
    
    def __str__(self):
        return f"{self.display_name} ({self.name})"
    
    def delete(self, *args, **kwargs):
        """Prevent deletion if page is linked to job roles"""
        if self.job_roles.exists():
            raise ValidationError(f"Cannot delete page '{self.name}' because it is linked to {self.job_roles.count()} job role(s)")
        return super().delete(*args, **kwargs)


class PageAction(models.Model):
    """PageAction model representing specific actions that can be performed on a page"""
    page = models.ForeignKey(Page, on_delete=models.CASCADE, related_name='actions')
    name = models.CharField(max_length=100, db_index=True)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'page_actions'
        unique_together = ('page', 'name')
    
    def __str__(self):
        return f"{self.page.name} - {self.display_name}"
    
    def delete(self, *args, **kwargs):
        """Prevent deletion if action has user denials"""
        if self.user_denials.exists():
            raise ValidationError(f"Cannot delete action '{self.name}' because it has {self.user_denials.count()} user denial(s)")
        return super().delete(*args, **kwargs)


class JobRolePage(models.Model):
    """Junction table linking job roles to their accessible pages"""
    job_role = models.ForeignKey(JobRole, on_delete=models.CASCADE, related_name='job_role_pages')
    page = models.ForeignKey(Page, on_delete=models.CASCADE, related_name='job_roles')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'job_role_pages'
        unique_together = ('job_role', 'page')
    
    def __str__(self):
        return f"{self.job_role.name} - {self.page.name}"


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


class UserActionDenial(models.Model):
    """User-specific action denials for page-based permissions"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='action_denials')
    page_action = models.ForeignKey(PageAction, on_delete=models.CASCADE, related_name='user_denials')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_action_denials'
        unique_together = ('user', 'page_action')
    
    def __str__(self):
        return f"{self.user.email} - DENIED - {self.page_action}"


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