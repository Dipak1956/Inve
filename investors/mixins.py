from django.contrib.auth.mixins import LoginRequiredMixin, AccessMixin
from django.core.exceptions import PermissionDenied
from django.contrib import messages
from django.shortcuts import redirect


class RoleRequiredMixin(AccessMixin):
    """
    Mixin to check if user has required role(s).
    Usage: required_roles = ['admin', 'partner']
    """
    required_roles = []
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            return self.handle_no_permission()
        
        user_role = request.user.role
        
        # Admin has access to everything
        if user_role == 'admin' or request.user.is_superuser:
            return super().dispatch(request, *args, **kwargs)
        
        # Check if user's role is in required roles
        if user_role in self.required_roles:
            return super().dispatch(request, *args, **kwargs)
        
        # Partner role allows access if 'partner' is in required_roles
        if user_role == 'partner' and 'partner' in self.required_roles:
            return super().dispatch(request, *args, **kwargs)
        
        messages.error(request, 'You do not have permission to access this page.')
        raise PermissionDenied


class AdminRequiredMixin(RoleRequiredMixin):
    """Mixin to require admin role"""
    required_roles = ['admin']


class PartnerRequiredMixin(RoleRequiredMixin):
    """Mixin to require partner or admin role"""
    required_roles = ['admin', 'partner']


class TeamMemberAccessMixin(LoginRequiredMixin):
    """
    Mixin to filter queryset based on user role.
    Team members only see assigned investors, partners/admins see all.
    """
    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        
        if user.is_admin or user.is_partner:
            # Admins and Partners see everything
            return qs
        elif user.is_team_member:
            # Team members only see their assigned investors
            if hasattr(qs.model, 'assigned_team_member'):
                return qs.filter(assigned_team_member=user)
        
        return qs.none()

