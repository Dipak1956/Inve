from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Investor, Deal, Commitment, Document, SecureLink


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User Admin with role field"""
    list_display = ['username', 'email', 'first_name', 'last_name', 'role', 'is_staff', 'is_active']
    list_filter = ['role', 'is_staff', 'is_active']
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Role Information', {'fields': ('role',)}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Role Information', {'fields': ('role',)}),
    )


@admin.register(Investor)
class InvestorAdmin(admin.ModelAdmin):
    """Investor Admin"""
    list_display = ['full_name', 'email', 'mobile', 'group', 'assigned_team_member', 'created_at']
    list_filter = ['group', 'assigned_team_member', 'created_at']
    search_fields = ['full_name', 'email', 'mobile', 'pan']
    readonly_fields = ['created_at', 'updated_at', 'get_masked_aadhaar']
    fieldsets = (
        ('Basic Information', {
            'fields': ('full_name', 'email', 'mobile', 'address', 'dob')
        }),
        ('KYC Information', {
            'fields': ('pan', 'aadhaar', 'get_masked_aadhaar')
        }),
        ('Investment Information', {
            'fields': ('investment_capacity', 'group')
        }),
        ('Relationships', {
            'fields': ('assigned_team_member', 'family_head')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_masked_aadhaar(self, obj):
        return obj.get_masked_aadhaar()
    get_masked_aadhaar.short_description = 'Aadhaar (Masked)'


@admin.register(Deal)
class DealAdmin(admin.ModelAdmin):
    """Deal Admin"""
    list_display = ['company_name', 'deal_size', 'ticket_size', 'round_no', 'status', 'workflow_status', 'created_at']
    list_filter = ['status', 'workflow_status', 'created_at']
    search_fields = ['company_name', 'description']
    readonly_fields = ['created_at', 'updated_at', 'created_by']
    fieldsets = (
        ('Basic Information', {
            'fields': ('company_name', 'description')
        }),
        ('Deal Details', {
            'fields': ('deal_size', 'ticket_size', 'round_no')
        }),
        ('Status', {
            'fields': ('status', 'workflow_status')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        if not change:  # Only set on creation
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Commitment)
class CommitmentAdmin(admin.ModelAdmin):
    """Commitment Admin"""
    list_display = ['investor', 'deal', 'amount', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['investor__full_name', 'investor__email', 'deal__company_name']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    """Document Admin"""
    list_display = ['title', 'document_type', 'content_type', 'object_id', 'uploaded_by', 'uploaded_at']
    list_filter = ['document_type', 'uploaded_at']
    search_fields = ['title', 'description']
    readonly_fields = ['uploaded_at', 'uploaded_by']
    
    def save_model(self, request, obj, form, change):
        if not change:  # Only set on creation
            obj.uploaded_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(SecureLink)
class SecureLinkAdmin(admin.ModelAdmin):
    """Secure Link Admin"""
    list_display = ['investor', 'token', 'expires_at', 'is_active', 'access_count', 'last_accessed_at', 'created_at']
    list_filter = ['is_active', 'expires_at', 'created_at']
    search_fields = ['investor__full_name', 'investor__email', 'token']
    readonly_fields = ['token', 'created_at', 'last_accessed_at', 'access_count']
    fieldsets = (
        ('Link Information', {
            'fields': ('investor', 'token', 'expires_at', 'is_active')
        }),
        ('Access Statistics', {
            'fields': ('access_count', 'last_accessed_at', 'created_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        if not change:  # Only set on creation
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
