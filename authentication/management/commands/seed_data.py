from django.core.management.base import BaseCommand
from authentication.models import UserType, CustomUser


class Command(BaseCommand):
    help = 'Seed database with initial user types and super admin'

    def handle(self, *args, **kwargs):
        # Create User Types
        self.stdout.write('Creating user types...')
        
        user_type, created = UserType.objects.get_or_create(
            type_name='user',
            defaults={'description': 'Regular user with basic permissions'}
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'✓ Created user type: {user_type.type_name}'))
        else:
            self.stdout.write(self.style.WARNING(f'- User type already exists: {user_type.type_name}'))
        
        admin_type, created = UserType.objects.get_or_create(
            type_name='admin',
            defaults={'description': 'Administrator with elevated permissions'}
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'✓ Created user type: {admin_type.type_name}'))
        else:
            self.stdout.write(self.style.WARNING(f'- User type already exists: {admin_type.type_name}'))
        
        super_admin_type, created = UserType.objects.get_or_create(
            type_name='super_admin',
            defaults={'description': 'Super administrator with full system access'}
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'✓ Created user type: {super_admin_type.type_name}'))
        else:
            self.stdout.write(self.style.WARNING(f'- User type already exists: {super_admin_type.type_name}'))
        
        # Create Super Admin
        self.stdout.write('\nCreating super admin...')
        
        super_admin_email = 'superadmin@lightidea.com'
        
        if CustomUser.objects.filter(email=super_admin_email).exists():
            self.stdout.write(self.style.WARNING(f'- Super admin already exists: {super_admin_email}'))
        else:
            super_admin = CustomUser.objects.create_superuser(
                email=super_admin_email,
                name='Super Admin',
                phone_number='+201234567890',
                password='SuperAdmin@123'
            )
            self.stdout.write(self.style.SUCCESS(f'✓ Created super admin: {super_admin.email}'))
            self.stdout.write(self.style.SUCCESS(f'  Password: SuperAdmin@123'))
            self.stdout.write(self.style.WARNING(f'  ⚠️  CHANGE THIS PASSWORD IN PRODUCTION!'))
        
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('Database seeding completed!'))
        self.stdout.write('='*50 + '\n')

