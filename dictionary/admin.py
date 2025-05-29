from django.contrib import admin
from .models import Tool
from import_export.admin import ExportMixin

@admin.register(Tool)
class ToolAdmin(admin.ModelAdmin):
    list_display = ('name', 'developer', 'is_approved', 'submitted_by')
    list_filter = ('is_approved',)
    actions = ['approve_tools']

    def approve_tools(self, request, queryset):
        queryset.update(is_approved=True)
    approve_tools.short_description = "Approve selected tools"