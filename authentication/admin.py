from django.contrib import admin
from .models import (
    CustomUser, UserType, JobRole,
    Page, PageAction, JobRolePage, UserActionDenial
)

# Register models for admin interface
admin.site.register(CustomUser)
admin.site.register(UserType)
admin.site.register(JobRole)
admin.site.register(Page)
admin.site.register(PageAction)
admin.site.register(JobRolePage)
admin.site.register(UserActionDenial)
