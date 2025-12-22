from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.core.exceptions import PermissionDenied


def role_required(*allowed_roles):
    """
    Decorator to check if user has one of the allowed roles.
    Usage: @role_required('admin', 'partner')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, 'Please login to access this page.')
                return redirect('login')
            
            user_role = request.user.role
            
            # Admin has access to everything
            if user_role == 'admin' or request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Check if user's role is in allowed roles
            if user_role in allowed_roles:
                return view_func(request, *args, **kwargs)
            
            # Partner role allows access if 'partner' is in allowed_roles
            if user_role == 'partner' and 'partner' in allowed_roles:
                return view_func(request, *args, **kwargs)
            
            messages.error(request, 'You do not have permission to access this page.')
            raise PermissionDenied
        
        return wrapper
    return decorator


def admin_required(view_func):
    """Decorator to require admin role"""
    return role_required('admin')(view_func)


def partner_required(view_func):
    """Decorator to require partner or admin role"""
    return role_required('admin', 'partner')(view_func)

