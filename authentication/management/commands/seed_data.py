from django.core.management.base import BaseCommand
from authentication.models import (
    UserType, CustomUser, JobRole,
    Page, PageAction, JobRolePage
)


class Command(BaseCommand):
    help = 'Seed database with initial user types, super admin, and page-based permission system data'

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
            super_admin = CustomUser.objects.get(email=super_admin_email)
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
        
        # ============================================
        # Page-Based Permission System Seed Data
        # ============================================
        
        self.stdout.write('\n' + '='*50)
        self.stdout.write('Setting up Page-Based Permission System...')
        self.stdout.write('='*50)
        
        # Create Job Role
        self.stdout.write('\nCreating job role: Accountant...')
        accountant_role, created = JobRole.objects.get_or_create(
            name='Accountant',
            defaults={'description': 'Handles financial records and transactions'}
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'✓ Created job role: {accountant_role.name}'))
        else:
            self.stdout.write(self.style.WARNING(f'- Job role already exists: {accountant_role.name}'))
        
        # Create Pages
        self.stdout.write('\nCreating pages...')
        
        # Invoice Page
        invoice_page, created = Page.objects.get_or_create(
            name='Invoice',
            defaults={
                'display_name': 'Invoice Management',
                'route': '/invoices',
                'description': 'Manage customer invoices'
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'✓ Created page: {invoice_page.name}'))
        else:
            self.stdout.write(self.style.WARNING(f'- Page already exists: {invoice_page.name}'))
        
        # Payment Page
        payment_page, created = Page.objects.get_or_create(
            name='Payment',
            defaults={
                'display_name': 'Payment Processing',
                'route': '/payments',
                'description': 'Process payments and transactions'
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'✓ Created page: {payment_page.name}'))
        else:
            self.stdout.write(self.style.WARNING(f'- Page already exists: {payment_page.name}'))
        
        # Reports Page
        reports_page, created = Page.objects.get_or_create(
            name='Reports',
            defaults={
                'display_name': 'Financial Reports',
                'route': '/reports',
                'description': 'View and generate financial reports'
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'✓ Created page: {reports_page.name}'))
        else:
            self.stdout.write(self.style.WARNING(f'- Page already exists: {reports_page.name}'))
        
        # Create Actions for Invoice Page
        self.stdout.write('\nCreating actions for Invoice page...')
        invoice_actions = [
            {'name': 'save_draft', 'display_name': 'Save Draft', 'description': 'Save invoice as draft'},
            {'name': 'submit_invoice', 'display_name': 'Submit Invoice', 'description': 'Submit invoice for approval'},
            {'name': 'approve_invoice', 'display_name': 'Approve Invoice', 'description': 'Approve pending invoice'},
            {'name': 'delete_invoice', 'display_name': 'Delete Invoice', 'description': 'Delete invoice'},
            {'name': 'export_invoice', 'display_name': 'Export Invoice', 'description': 'Export invoice to PDF'},
            {'name': 'view_invoice', 'display_name': 'View Invoice', 'description': 'View invoice details'},
        ]
        
        for action_data in invoice_actions:
            action, created = PageAction.objects.get_or_create(
                page=invoice_page,
                name=action_data['name'],
                defaults={
                    'display_name': action_data['display_name'],
                    'description': action_data.get('description', '')
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created action: {action.name}'))
            else:
                self.stdout.write(self.style.WARNING(f'  - Action already exists: {action.name}'))
        
        # Create Actions for Payment Page
        self.stdout.write('\nCreating actions for Payment page...')
        payment_actions = [
            {'name': 'generate_payment', 'display_name': 'Generate Payment', 'description': 'Generate new payment'},
            {'name': 'approve_payment', 'display_name': 'Approve Payment', 'description': 'Approve pending payment'},
            {'name': 'cancel_payment', 'display_name': 'Cancel Payment', 'description': 'Cancel payment'},
            {'name': 'view_payment_history', 'display_name': 'View Payment History', 'description': 'View payment history'},
            {'name': 'process_refund', 'display_name': 'Process Refund', 'description': 'Process payment refund'},
        ]
        
        for action_data in payment_actions:
            action, created = PageAction.objects.get_or_create(
                page=payment_page,
                name=action_data['name'],
                defaults={
                    'display_name': action_data['display_name'],
                    'description': action_data.get('description', '')
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created action: {action.name}'))
            else:
                self.stdout.write(self.style.WARNING(f'  - Action already exists: {action.name}'))
        
        # Create Actions for Reports Page
        self.stdout.write('\nCreating actions for Reports page...')
        reports_actions = [
            {'name': 'view_report', 'display_name': 'View Report', 'description': 'View report'},
            {'name': 'generate_report', 'display_name': 'Generate Report', 'description': 'Generate new report'},
            {'name': 'export_report', 'display_name': 'Export Report', 'description': 'Export report'},
            {'name': 'schedule_report', 'display_name': 'Schedule Report', 'description': 'Schedule automatic report'},
            {'name': 'delete_report', 'display_name': 'Delete Report', 'description': 'Delete report'},
        ]
        
        for action_data in reports_actions:
            action, created = PageAction.objects.get_or_create(
                page=reports_page,
                name=action_data['name'],
                defaults={
                    'display_name': action_data['display_name'],
                    'description': action_data.get('description', '')
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created action: {action.name}'))
            else:
                self.stdout.write(self.style.WARNING(f'  - Action already exists: {action.name}'))
        
        # Link Pages to Job Role
        self.stdout.write('\nLinking pages to Accountant job role...')
        for page in [invoice_page, payment_page, reports_page]:
            job_role_page, created = JobRolePage.objects.get_or_create(
                job_role=accountant_role,
                page=page
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Linked page: {page.name}'))
            else:
                self.stdout.write(self.style.WARNING(f'  - Page already linked: {page.name}'))
        
        # Create Sample Users
        self.stdout.write('\nCreating sample users...')
        
        # Senior Accountant (Ahmed)
        ahmed_email = 'ahmed@lightidea.com'
        if not CustomUser.objects.filter(email=ahmed_email).exists():
            ahmed = CustomUser.objects.create_user(
                email=ahmed_email,
                name='Ahmed Hassan',
                phone_number='+201111111111',
                password='Ahmed@123',
                user_type=admin_type
            )
            ahmed.job_role = accountant_role
            ahmed.save()
            self.stdout.write(self.style.SUCCESS(f'✓ Created user: {ahmed.email} (Senior Accountant)'))
            self.stdout.write(self.style.SUCCESS(f'  Password: Ahmed@123'))
        else:
            self.stdout.write(self.style.WARNING(f'- User already exists: {ahmed_email}'))
        
        # Junior Accountant (Sara)
        sara_email = 'sara@lightidea.com'
        if not CustomUser.objects.filter(email=sara_email).exists():
            sara = CustomUser.objects.create_user(
                email=sara_email,
                name='Sara Ahmed',
                phone_number='+201222222222',
                password='Sara@123',
                user_type=user_type
            )
            sara.job_role = accountant_role
            sara.save()
            self.stdout.write(self.style.SUCCESS(f'✓ Created user: {sara.email} (Junior Accountant)'))
            self.stdout.write(self.style.SUCCESS(f'  Password: Sara@123'))
            self.stdout.write(self.style.WARNING(f'  Note: To deny specific actions for Sara, use the API endpoints'))
        else:
            self.stdout.write(self.style.WARNING(f'- User already exists: {sara_email}'))
        
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('Database seeding completed!'))
        self.stdout.write('='*50)
        self.stdout.write('\n📝 Sample Users Created:')
        self.stdout.write('  1. Super Admin: superadmin@lightidea.com (SuperAdmin@123)')
        self.stdout.write('  2. Senior Accountant (Admin): ahmed@lightidea.com (Ahmed@123)')
        self.stdout.write('  3. Junior Accountant (User): sara@lightidea.com (Sara@123)')
        self.stdout.write('\n📚 Pages Created: Invoice, Payment, Reports')
        self.stdout.write('💼 Job Role: Accountant (with access to all 3 pages)')
        self.stdout.write('\n⚠️  IMPORTANT: Change all passwords in production!')
        self.stdout.write('='*50 + '\n')

