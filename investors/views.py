from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView, FormView
from django.urls import reverse_lazy
from django.db.models import Q, Sum, Case, When, F, Value, DecimalField
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
import uuid
from decimal import Decimal
from django.urls import reverse

from .models import User, Investor, Deal, Commitment, Document, SecureLink ,AuditLog, MyModel, DealInternalNote
from .mixins import RoleRequiredMixin, PartnerRequiredMixin, AdminRequiredMixin, TeamMemberAccessMixin
from .decorators import role_required, partner_required, admin_required
from .forms import InvestorForm, ExternalInvestorForm, DealForm, DealInterestForm, OTPVerificationForm, HierarchicalUserCreationForm, DealSendForm, CommitmentForm, InvestorBulkUploadForm, DealInternalNoteForm
from .utils import send_deal_closure_email, send_deal_invitation, send_payment_request, generate_deal_email_content, send_mail_via_user_credentials, send_otp_email,send_confirmation_email, send_rejected_email, send_deal_invitation_via_whatspp, send_thankyou_email_not_committed
from django.contrib.auth.forms import SetPasswordForm
from openpyxl import Workbook
from django.http import HttpResponse
from io import BytesIO
import pandas as pd
from django.db.models import Value
from django.contrib.postgres.aggregates import StringAgg
from django.contrib.messages.views import SuccessMessageMixin
import io
from django.http import FileResponse
from datetime import datetime
from django import forms
from django.shortcuts import render, get_object_or_404, redirect
from .forms import MyModelForm
from ckeditor.widgets import CKEditorWidget
import csv
import bcrypt
import hashlib
from django.db import IntegrityError, transaction
import traceback
from django.core.files.base import ContentFile

def get_sender_credentials(user):
    """
    Helper to find the correct Admin credentials.
    Logic:
    1. If the logged-in user was created by someone (e.g., Partner created by Admin),
       fetch the Admin/Creator's credentials.
    2. If the logged-in user has no creator (is the Super Admin), use their own.
    """
    if user.created_by:
        print("Using Admin credentials.")
        # Use the Admin's credentials (The user who created this partner)
        sender_user = user.created_by
        print(f"Sender User: {sender_user}")
        email = sender_user.email if sender_user.email else sender_user.email
        password = sender_user.smtp_password
        return email, password, sender_user.username
    else:
        # User is likely the Admin (has no creator), use their own
        email = user.smtp_email if user.smtp_email else user.email
        password = user.smtp_password
        return email, password, user.username
    
def log_activity(user, obj, action, changes=None):
    if user.is_authenticated:
        AuditLog.objects.create(
            user=user,
            content_type=ContentType.objects.get_for_model(obj),
            object_id=obj.id,
            action=action,
            changes=changes
        )
        
class UserManagementView(PartnerRequiredMixin, ListView):
    """
    Dashboard to manage all system users (Partners & Team Members).
    Separates them into two lists for easy management.
    """
    model = User
    template_name = 'investors/user_list.html'
    context_object_name = 'users'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get all users except the current user
        all_users = User.objects.exclude(pk=self.request.user.pk).order_by('-date_joined')
        
        # Split into categories
        context['partners'] = all_users.filter(role='partner')
        context['team_members'] = all_users.filter(role='team_member')
        
        return context

class UserDetailView(TeamMemberAccessMixin, DetailView):
    """
    View full profile and configuration of a specific user.
    """
    model = User
    template_name = 'investors/user_detail.html'
    context_object_name = 'profile_user'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Show stats for this user
        user = self.get_object()
        
        if user.role == 'team_member':
            context['assigned_investors_count'] = Investor.objects.filter(assigned_team_members=user).count()
        elif user.role == 'partner':
            context['deals_created_count'] = Deal.objects.filter(created_by=user).count()
            
        return context

class UserUpdateView(PartnerRequiredMixin, UpdateView):
    """
    Edit User Configuration (Email, Role, Active Status).
    """
    model = User
    template_name = 'investors/user_form_edit.html'
    context_object_name = 'profile_user'
    fields = ['username', 'first_name', 'last_name', 'email', 'role', 'is_active', 'smtp_password']
    success_url = reverse_lazy('investors:user_list')
    
    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        if self.request.user.role == 'admin':        
            form.fields['role'].choices = [ 
                ('partner', 'Partner'),
                ('team_member', 'Team Member'),
            ]

        elif self.request.user.role == 'partner':
            form.fields['role'].choices = [
                ('team_member', 'Team Member'),
            ]
        
        # SAFETY CHECK: If editing MYSELF, disable Role and Active fields
        if self.object == self.request.user:
            form.fields['role'].choices = [
                ('admin', 'Admin'),
                ('partner', 'Partner'),
            ]
            form.fields['role'].disabled = True
            form.fields['is_active'].disabled = True
            form.fields['role'].help_text = "You cannot change your own role."
            form.fields['is_active'].help_text = "You cannot deactivate your own account."
        return form
    
    def form_valid(self, form):
        messages.success(self.request, f"User {self.object.username} updated successfully.")
        return super().form_valid(form)


@login_required
def user_password_reset(request, pk):
    """
    Admin can reset credentials (password) for a user manually.
    """
    print("-----------------------", request.user)
    # if not request.user.is_admin or request.user.is_partner:
    #     messages.error(request, "Permission denied.")
    #     return redirect('investors:dashboard')
        
    user_to_reset = get_object_or_404(User, pk=pk)
    
    if request.method == 'POST':
        form = SetPasswordForm(user_to_reset, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, f"Password for {user_to_reset.username} has been changed successfully.")
            return redirect('investors:user_detail', pk=pk)
    else:
        form = SetPasswordForm(user_to_reset)
        
    return render(request, 'investors/user_password_reset.html', {'form': form, 'profile_user': user_to_reset})

class UserCreateView(LoginRequiredMixin, CreateView):
    model = User
    form_class = HierarchicalUserCreationForm
    template_name = 'investors/user_form.html'
    context_object_name = 'profile_user'
    success_url = reverse_lazy('investors:dashboard')
    optional_fields = ["pan", "aadhaar", "ticket_size_preference"]

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['creator'] = self.request.user
        return kwargs

    def dispatch(self, request, *args, **kwargs):
        # Security check: Only Admins or Partners can create users
        if not (request.user.is_admin or request.user.is_partner):
            messages.error(request, "You do not have permission to create users.")
            return redirect('investors:dashboard')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save(commit=False)
        user.set_password(form.cleaned_data['password'])
        user.created_by = self.request.user
        user.save()
        messages.success(self.request, f"User {user.username} created successfully as {user.get_role_display()}.")
        return super().form_valid(form)    

@login_required
def send_deal_view(request, pk):
    resend_invite = False
    deal = get_object_or_404(Deal, pk=pk)
    preview_data = None  # Variable to store preview content
    
    # Get IDs of investors who already have commitments for this deal
    already_invited_ids = list(Commitment.objects.filter(deal=deal).values_list('investor_id', flat=True))
    
    if request.method == 'POST':
        form = DealSendForm(request.POST, user=request.user)
        
        # Check if user clicked "Preview" or "Send"
        action = request.POST.get('action') 

        if form.is_valid():
            selected_investors = form.cleaned_data['investors']
            days = form.cleaned_data['expiry_days']
            template = form.cleaned_data.get('existing_template')
            
            custom_content = request.POST.get('content')
            custom_subject = request.POST.get('subject')

            # Determine if this is a template-driven update
            is_template_load = action == 'load_template' or (not action and template)
            
            # --- ACTION: PREVIEW or TEMPLATE LOAD ---
            if action == 'preview' or is_template_load:
                first_investor = selected_investors.first()
                if first_investor:
                    expiry_date = timezone.now() + timezone.timedelta(days=days)
                    # Create a dummy link for rendering variables if needed
                    link = SecureLink.objects.create(
                        investor=first_investor,
                        expires_at=expiry_date,
                        created_by=request.user,
                        is_active=True
                    )
                    
                    if is_template_load and template:
                        subject = f"Invitation: Investment Opportunity in {deal.company_name}"
                        body = template.content
                    elif custom_content:
                        subject = custom_subject
                        body = custom_content
                    else:
                        subject, body = generate_deal_email_content(request, first_investor, deal, link)
                    
                    # RENDER placeholders only for the PREVIEW box
                    try:
                        preview_subject, preview_body = generate_deal_email_content(
                            request, first_investor, deal, link, 
                            custom_subject=subject, 
                            custom_content=body
                        )
                    except Exception as e:
                        preview_subject, preview_body = "", ""
                        messages.warning(request, "This Template is not configured for this email content.")
                        
                    preview_data = {
                        'investor': first_investor.full_name,
                        'subject': preview_subject,
                        'body': preview_body
                    }
                    
                    form = DealSendForm(initial={
                        'investors': selected_investors,
                        'expiry_days': days,
                        'subject': subject,
                        'content': body,
                        'existing_template': template
                    }, user=request.user)
                    
                    if action == 'preview':
                        messages.info(request, "Preview generated below. Review before sending.")
                        
            # --- ACTION: SEND ---
            elif action == 'send':
                count = 0
                errors = 0
                
                # Check credentials first
                if not request.user.email or not request.user.smtp_password:
                    messages.error(request, "Please configure your Email and App Password in your User Profile first.")
                    return redirect('investors:user_detail', pk=request.user.pk)

                for investor in selected_investors:
                    # 1. Create Link
                    expiry_date = timezone.now() + timezone.timedelta(days=days)
                    link = SecureLink.objects.create(
                        investor=investor,
                        expires_at=expiry_date,
                        created_by=request.user,
                        is_active=True
                    )
                    
                    # Always use generate_deal_email_content to render placeholders
                    # for THIS specific investor, passing custom content if available.
                    custom_content = request.POST.get('content')
                    custom_subject = request.POST.get('subject')
                    
                    subject, body = generate_deal_email_content(
                        request, investor, deal, link,
                        custom_subject=custom_subject,
                        custom_content=custom_content
                    )
                    
                    existing_commitment_obj = Commitment.objects.filter(investor=investor, deal=deal).first()
                    force_send = request.POST.get('force_send') == 'true'
                    
                    if not existing_commitment_obj or force_send:
                        success, msg = send_mail_via_user_credentials(request, investor, subject, body)
                        if success:
                            count += 1
                            if not existing_commitment_obj:
                                Commitment.objects.create(
                                    investor=investor, 
                                    deal=deal,
                                    status='pending'
                                )
                            # If force_send, we just re-sent the email, no need to create/update commitment if it exists
                        else:
                            errors += 1
                    else:
                        # This case should technically be handled by the frontend popup now,
                        # but keeping a message for safety if someone bypasses it.
                        messages.warning(request, f"{investor.full_name} Invitation already sent for this deal.")   
                                        
                        
                if count > 0:
                    messages.success(request, f"Sent {count} emails using {request.user.smtp_email}.")
                if errors > 0:
                    messages.warning(request, f"Failed to send {errors} emails. Check your App Password.")
                
                return redirect('investors:deal_detail', pk=pk)
            
    else:
        form = DealSendForm(user=request.user)

    return render(request, 'investors/deal_send.html', {
        'deal': deal, 
        'form': form, 
        'preview_data': preview_data, # Pass preview to template
        'already_invited_ids': already_invited_ids
    })
    
@login_required
def approve_commitment(request, pk): 
    """
    User clicks 'Approve' -> System updates status -> Sends Payment Email
    """
    commitment = get_object_or_404(Commitment, pk = pk)
    
    # Security: Ensure only partners/admin can approve
    if not (request.user.is_partner or request.user.is_admin):
        messages.error(request, "Permission denied.")
        return redirect('investors:dashboard')
    
    if commitment.status in ['interested', 'committed', 'approved']:
        # Update Status
        commitment.status = 'approved'
        commitment.approved_amount = commitment.amount
        commitment.save()
        
        # AUTOMATION: Send Payment Email
        email_sent, error_msg = send_payment_request(request, commitment)
        
        if email_sent:
            messages.success(request, f"Commitment approved! Payment request sent to {commitment.investor.full_name}.")
        else:
            messages.warning(request, f"Commitment approved, but email failed: {error_msg}")
        
    
    return redirect('investors:deal_dashboard', deal_id = commitment.deal.id) 
        
def payment_link_access(request, token):
    """
    Step 1: User clicks payment link.
    System generates OTP, sends email, and prepares redirect to Upload Page.
    """    
    try:
        secure_link = get_object_or_404(SecureLink, token=token)
    except SecureLink.DoesNotExist:
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Link Not Found',
            'error_message': 'The provided link does not exist. Please contact support for assistance.'
        }, status=404)
    
    # Check if link is valid
    if not secure_link.is_valid():
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Link Expired',
            'error_message': 'This link has expired or been deactivated. Please contact support for a new link.'
        }, status=403)

    # Generate OTP
    #otp = secure_link.generate_otp()
    #if secure_link.investor.family_head_id:
    #   investor = secure_link.investor.family_head
    #else:
    #    investor = secure_link.investor
        
    # Send OTP email
    #link_creator = secure_link.created_by
    #if link_creator:
    #    send_otp_email(link_creator, investor, otp, request)
    
    # Store token in session for verification
    request.session['verification_token'] = str(token)
    request.session[f'auth_{str(token)}'] = True
    
    return redirect('investors:upload_payment', token=token)

def upload_payment_view(request, token):
    """
    Investor clicks link in email -> Uploads proof
    """
    if not request.session.get(f'auth_{str(token)}'):
        return redirect('investors:payment_link_access', token=token)
    
    secure_link = get_object_or_404(SecureLink, token=token)
    
    # 2. Check if link is still valid (Double check)
    if not secure_link.is_valid():
        return render(request, 'investors/error.html', {'message': 'This upload link has expired.'})
        
    commitment = secure_link.commitment
    if not commitment:
        return render(request, 'investors/error.html', {'message': 'No commitment linked to this token.'})
    
    if request.method == 'POST':
        if 'payment_proof' in request.FILES:
            commitment.payment_proof = request.FILES['payment_proof']
            commitment.status = 'payment_uploaded'
            commitment.save()
            
            secure_link.is_active = False
            secure_link.save()
            
            return render(request, 'investors/success.html', {
                'msg': 'Payment proof uploaded successfully! The link is now deactivated.'
            })
    
    return render(request, 'investors/upload_payment.html', {'commitment': commitment})

def active_invester(request, pk):
    investor = get_object_or_404(Investor, pk = pk)
    investor.is_active = True
    investor.save()
    return redirect('investors:investor_list')

def approv_deal(request, pk):
    deal = get_object_or_404(Deal, pk = pk)
    deal.status = 'approved'
    deal.save()
    return redirect('investors:deal_list')    

@login_required
def confirm_commitment(request, pk):
    """
    User verifies proof -> Clicks Confirm -> Deal Closed
    """
    
    commitment = get_object_or_404(Commitment, pk=pk)
    
    if request.user.is_partner or request.user.is_team_member:
        commitment.status = 'confirmed'
        commitment.save()
        success, msg = send_confirmation_email(request, commitment)
        
        # 3. User Feedback
        if success:
            messages.success(request, f"Payment verified! Confirmation email sent to {commitment.investor.full_name}.")
        else:
            messages.warning(request, f"Payment verified, but email failed: {msg}")
    
    return redirect('investors:deal_dashboard', deal_id=commitment.deal.id)
        
def external_access_otp(request, token):
    """
    Step 1: User clicks link, enters this view.
    System generates OTP, sends it (simulated), and redirects to verification page.
    """
    try:
        token_uuid = uuid.UUID(str(token))
        secure_link = SecureLink.objects.get(token=token_uuid)
    except (ValueError, TypeError, SecureLink.DoesNotExist):
        return render(request, 'investors/error.html', {'message': 'Invalid Link'})

    if not secure_link.is_valid():
        return render(request, 'investors/error.html', {'message': 'Link Expired'})

    # Generate OTP
    otp = secure_link.generate_otp()
    
    link_creator = secure_link.created_by
    
    if link_creator:
        send_otp_email(link_creator, secure_link.investor, otp, request)
    else:
        # Fallback if the link creator was deleted or not set
        print("Error: No creator found for this link. OTP not sent via email.")
    
    # TODO: Integrate Email/SMS API here to send 'otp'
    print(f"DEBUG: OTP for {secure_link.investor.email} is {otp}") 
    
    # Store token in session to verify later
    request.session['verification_token'] = str(token)
    return redirect('investors:verify_otp')

def verify_otp_view(request):
    """Step 2: User enters OTP."""
    token_str = request.session.get('verification_token')
    if not token_str:
        return redirect('investors:login')
    
    secure_link = get_object_or_404(SecureLink, token=token_str)
    
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            if secure_link.verify_otp(form.cleaned_data['otp']):
                # OTP Verified - Set session flag
                request.session[f'auth_{token_str}'] = True
                next_url = request.session.pop('next_url', None)
                if next_url:
                    return redirect(next_url)
                
                # Redirect based on context (Investor Profile or Deal Interest)
                # NOTE: You might need separate secure links or a 'type' field on SecureLink 
                # to know where to redirect. Defaulting to profile form here.
                return redirect('investors:external_investor_form', token=token_str)
            else:
                messages.error(request, "Invalid or Expired OTP")
    else:
        form = OTPVerificationForm()

    if secure_link.investor.family_head_id:
        context = {'form': form, 'email': secure_link.investor.family_head.email}
    else:
        context = {'form': form}    
    return render(request, 'investors/otp_verify.html', context)

def is_admin_or_partner(user):
    """Test function for user_passes_test decorator"""
    return user.is_authenticated and (user.is_admin or user.is_partner)

def InvestorSelfSignUp(request):
    optional_fields = ["dob", "profession", "address", "pan", "aadhaar", "risk_appetite", "preferred_duration", "ticket_size_preference", "bank_name", "account_number", "ifsc_code", "dp_id", "client_id", "referred_by", "investment_capacity", "group", 'preferred_industries']
    
    if request.method == "POST":  
        form = InvestorForm(request.POST)
        
        # Apply optional fields logic to the form instance receiving POST data
        for field in optional_fields:
            if field in form.fields:
                form.fields[field].required = False
                
        if form.is_valid():
            form.save()            
            messages.success(request, "Investor Sign up successful! 🎉")
            request.session['form_submitted'] = True
            return render(request, 'investors/login.html')
        else:
            messages.warning(request, "Unable to Sign up Sorry")
            return render(request, 'investors/investor_signup_self.html', {'form': form})
    
    # GET request
    form = InvestorForm()
    # Apply optional fields logic for initial display
    for field in optional_fields:
        if field in form.fields:
            form.fields[field].required = False
            
    return render(request, 'investors/investor_signup_self.html', {'form': form})

def login_view(request):
    """Custom login view"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
            return redirect('investors:dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'investors/login.html')

@login_required
def dashboard(request):
    """
    Dashboard view with overview statistics.
    Shows different stats based on user role:
    - Admin/Partner: ALL investors and deals
    - Team Member: ONLY assigned investors
    """
    user = request.user
    
    # Statistics based on user role
    if user.is_admin or user.is_partner:
        # Admin/Partner: Show ALL investors and deals
        total_investors = Investor.objects.count()
        total_deals = Deal.objects.count()
        total_commitments = Commitment.objects.count()
        total_commitment_amount = Commitment.objects.aggregate(
            total=Sum('amount')
        )['total'] or 0
        
        # Group statistics
        group_a_count = Investor.objects.filter(group='A').count()
        group_b_count = Investor.objects.filter(group='B').count()
        group_c_count = Investor.objects.filter(group='C').count()
        
        # Status statistics for deals   
        new_deals = Deal.objects.filter(status='new').count()
        active_deals = Deal.objects.filter(status='active').count()
        closing_deals = Deal.objects.filter(status='closing').count()
        closed_deals = Deal.objects.filter(status='closed').count()
        
        # Recent investors (all)
        recent_investors = Investor.objects.all()[:5]
    else:
        # Team Member: Show ONLY assigned investors
        assigned_investors = Investor.objects.filter(assigned_team_members=user)
        investor_ids = assigned_investors.values_list('id', flat=True)
        
        total_investors = assigned_investors.count()
        total_deals = Deal.objects.count()  # They can see all deals
        total_commitments = Commitment.objects.filter(investor_id__in=investor_ids).count()
        total_commitment_amount = Commitment.objects.filter(
            investor_id__in=investor_ids
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Group statistics (only for assigned investors)
        group_a_count = assigned_investors.filter(group='A').count()
        group_b_count = assigned_investors.filter(group='B').count()
        group_c_count = assigned_investors.filter(group='C').count()
        
        # Status statistics for deals (all deals visible)
        new_deals = Deal.objects.filter(status='new').count()
        active_deals = Deal.objects.filter(status='active').count()
        closing_deals = Deal.objects.filter(status='closing').count()
        closed_deals = Deal.objects.filter(status='closed').count()
        
        # Recent investors (only assigned)
        recent_investors = assigned_investors
    
    # Recent deals (all users see all deals)
    recent_deals = Deal.objects.select_related('created_by').all()[:5]
    
    # Recent commitments based on user role
    if user.is_admin or user.is_partner:
        recent_commitments = Commitment.objects.select_related('investor', 'deal').all()[:5]
    else:
        investor_ids = Investor.objects.filter(assigned_team_members=user).values_list('id', flat=True)
        recent_commitments = Commitment.objects.filter(
            investor_id__in=investor_ids
        ).select_related('investor', 'deal').all()[:5]
    
    context = {
        'total_investors': total_investors,
        'total_deals': total_deals,
        'total_commitments': total_commitments,
        'total_commitment_amount': total_commitment_amount,
        'group_a_count': group_a_count,
        'group_b_count': group_b_count,
        'new_deals': new_deals,
        'active_deals': active_deals,
        'closing_deals': closing_deals,
        'closed_deals': closed_deals,
        'recent_investors': recent_investors,
        'recent_deals': recent_deals,
        'recent_commitments': recent_commitments,
        'is_admin_or_partner': user.is_admin or user.is_partner,
    }
    
    return render(request, 'investors/dashboard.html', context)

# Investor Views
class InvestorListView(LoginRequiredMixin, ListView):
    model = Investor
    template_name = 'investors/investor_list.html'
    context_object_name = 'investors'
    paginate_by = 20
    industries = Investor.INDUSTRY_CHOICES
        
    def get_queryset(self):
        user = self.request.user
        # Filter by user role: Team members only see assigned investors
        if user.is_team_member:
            qs = Investor.objects.filter(Q(assigned_team_members=user) | Q(created_by=user)).distinct()
        else:
            # Admin/Partner see all investors
            qs = Investor.objects.all()
        
        # Apply search filter
        search = self.request.GET.get('search', '')
        if search:
            qs = qs.filter(
                Q(full_name__icontains=search) |
                Q(email__icontains=search) |
                Q(mobile__icontains=search) |
                Q(pan__icontains=search)
            )
            
        # Apply Active Filter
        active_filter = self.request.GET.get('is_active', '')   
        if active_filter:
            qs = qs.filter(is_active=active_filter)

        # Apply group filter
        group_filter = self.request.GET.get('group', '')
        if group_filter:
            qs = qs.filter(group=group_filter)
            
        # Apply industry filter
        industry_filter = self.request.GET.getlist('industry', [])
        if industry_filter:
            unique_industries = list(set(industry_filter)) 
            query = Q()
            for industry in unique_industries:
                query |= Q(preferred_industries__icontains=f'"{industry}"')
            qs = qs.filter(query)
        
        # Apply team member filter (Admin/Partner only)
        if not user.is_team_member:
            team_member_filter = self.request.GET.get('team_member', '')
            if team_member_filter:
                qs = qs.filter(Q(assigned_team_members=team_member_filter) | Q(created_by=team_member_filter)).distinct()    
        
        return qs.prefetch_related('assigned_team_members').select_related('family_head')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context['industries'] = list(self.industries)
        
        # Add filter options for admin/partner
        if not user.is_team_member:
            context['team_members'] = User.objects.filter(role='team_member')    
        return context   
    
    def post(self, request, *args, **kwargs):
        if 'export_excel' in request.POST:
            queryset = self.get_queryset().prefetch_related('assigned_team_members')
            data = []
            for obj in queryset:
                data.append({
                    'Full_name': obj.full_name,
                    'Email': obj.email,
                    'Mobile': obj.mobile,
                    'Investment Capicity': obj.group,
                    'Address': obj.address,
                    'Family Head': obj.family_head.full_name if obj.family_head else 'Self',
                    'Remark': obj.remark,
                    'Referred By': obj.referred_by,
                    'Profession': obj.profession,
                    'Created By': obj.created_by.username,
                    'Assigned Team Members': ", ".join(
                        obj.assigned_team_members.values_list('username', flat=True)
                    )
                })
            
            df = pd.DataFrame(data)
            df.rename(columns={'assigned_team_members': 'Team Member'}, inplace=True)
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Investors')
            output.seek(0)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"investors_list_{timestamp}.xlsx"
            
            response = HttpResponse(
                output.read(), 
                content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        
        return super().get(request, *args, **kwargs)
    
class InvestorDetailView(LoginRequiredMixin, DetailView):
    model = Investor
    template_name = 'investors/investor_detail.html'
    context_object_name = 'investor'
    
    def get_queryset(self):
        qs = super().get_queryset()        
        user = self.request.user
        if user.is_team_member:
            # Check if investor is assigned to this team member
            investor = qs.filter(id = self.kwargs['pk']).first()
            if investor and user not in investor.assigned_team_members.all():
                return qs.none()
        return qs
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        investor = self.get_object()

        # Get individual commitments
        context['commitments'] = Commitment.objects.filter(investor=investor).select_related('deal')
        context['total_commitment_amount'] = Commitment.objects.filter(
            investor=investor
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Get documents
        context['documents'] = Document.objects.filter(
            content_type=ContentType.objects.get_for_model(Investor),
            object_id=investor.id
        )
        
        # Family view data
        # Get family head if this investor is a family member
        family_head = investor.family_head
        # Get family members if this investor is a family head
        family_members = investor.family_members.all()
        
        # Determine the primary investor (family head)
        primary_investor = family_head if family_head else investor
        
        # Get all family investors (primary + members)
        if primary_investor == investor:
            # This investor is the family head
            family_investors = [investor] + list(family_members)
        else:
            # This investor is a family member
            family_investors = [primary_investor] + list(primary_investor.family_members.all())
        
        family_investor_ids = [inv.pk for inv in family_investors]
        
        # Aggregate family commitments
        family_commitments = Commitment.objects.filter(
            investor_id__in=family_investor_ids
        ).select_related('investor', 'deal')
        
        family_total_amount = Commitment.objects.filter(
            investor_id__in=family_investor_ids
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Group commitments by deal for family view
        family_commitments_by_deal = {}
        for commitment in family_commitments:
            deal_name = commitment.deal.company_name
            if deal_name not in family_commitments_by_deal:
                family_commitments_by_deal[deal_name] = {
                    'deal': commitment.deal,
                    'total_amount': 0,
                    'investors': []
                }
            family_commitments_by_deal[deal_name]['total_amount'] += commitment.amount
            family_commitments_by_deal[deal_name]['investors'].append({
                'investor': commitment.investor,
                'amount': commitment.amount,
                'status': commitment.status
            })
        
        context['family_head'] = family_head
        context['family_members'] = family_members
        context['primary_investor'] = primary_investor
        context['family_investors'] = family_investors
        context['family_commitments'] = family_commitments
        context['family_total_amount'] = family_total_amount
        context['family_commitments_by_deal'] = family_commitments_by_deal
        
        return context

class InvestorCreateView(LoginRequiredMixin, CreateView):
    model = Investor
    form_class = InvestorForm
    template_name = 'investors/investor_form.html'
    success_url = reverse_lazy('investors:investor_list')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def form_valid(self, form):
        response = super().form_valid(form)
        log_activity(self.request.user, self.object, 'create')
        return response

    def form_invalid(self, form):
        print(form.errors)
        return super().form_invalid(form)    

class InvestorUpdateView(LoginRequiredMixin, UpdateView):
    model = Investor
    form_class = InvestorForm
    template_name = 'investors/investor_form.html'
    success_url = reverse_lazy('investors:investor_list')
    
    def get_queryset(self):
        user = self.request.user        
        if user.is_admin or user.is_partner:
            return Investor.objects.all()
        # Team members can only update their assigned investors
        return Investor.objects.filter(assigned_team_members=user)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def form_valid(self, form):        
        if form.has_changed():
            # Basic change tracking
            changes = {}
            print('form.changed_data', form.changed_data)
            for field in form.changed_data:
                val = form.cleaned_data.get(field)
                # Skip ManyToMany fields - they cause JSON serialization issues
                if field == 'assigned_team_members':
                    if val:
                        changes[field] = [str(user) for user in val]
                    else:
                        changes[field] = []
                # Handle date/datetime objects for JSON serialization
                elif hasattr(val, 'isoformat'):
                    changes[field] = val.isoformat()
                elif isinstance(val, (Decimal, uuid.UUID)):
                    changes[field] = str(val)
                elif hasattr(val, 'pk'):
                    changes[field] = str(val)
                else:
                    changes[field] = val
            
            log_activity(self.request.user, self.object, 'update', changes=changes)
        return super().form_valid(form)

class InvestorDeleteView(AdminRequiredMixin, DeleteView):
    model = Investor
    template_name = 'investors/investor_confirm_delete.html'
    success_url = reverse_lazy('investors:investor_list')
    
    def delete(self, request, *args, **kwargs):        
        messages.success(self.request, 'Investor deleted successfully.')
        return super().delete(request, *args, **kwargs)

# Deal Views
class DealListView(LoginRequiredMixin, ListView):
    model = Deal
    template_name = 'investors/deal_list.html'
    context_object_name = 'deals'
    paginate_by = 20
    
    def get_queryset(self):
        user = self.request.user
        # For team members: show deals created by them OR assigned to them
        if user.is_team_member:
            qs = Deal.objects.filter(
                Q(created_by=user) | Q(assigned_team_members=user, workflow_status='approved')
            ).distinct()
        else:
            # Admin/Partner: show all deals
            qs = Deal.objects.all()
        
        search = self.request.GET.get('search', '')
        status_filter = self.request.GET.get('status', '')
        
        if search:
            qs = qs.filter(
                Q(company_name__icontains=search) |
                Q(description__icontains=search)
            )
        if status_filter:
            qs = qs.filter(status=status_filter)
        
        return qs.select_related('created_by').prefetch_related('assigned_team_members')

class DealDetailView(LoginRequiredMixin, DetailView):
    model = Deal
    template_name = 'investors/deal_detail.html'
    context_object_name = 'deal'

    
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        deal = self.get_object()
        user = self.request.user
        EXPECTED_TITLES = [
            ('One pager', 'one_pager'),
            ('Pitch Deck', 'pitch_deck'),
            ('Financials', 'financials'),            
            ('Write Up', 'write_up'),
            ('Term Sheet', 'term_sheet'),
            ('Projections', 'projections'),
        ]

        commitments_qs = Commitment.objects.filter(deal=deal)
        context['commitments'] = commitments_qs
        
        totals = commitments_qs.aggregate(
            total_proposal=Sum(
                Case(
                    When(
                        Q(status__in=['pending', 'rejected', 'committed', 'payment_uploaded']) & 
                        (~Q(amount=F('approved_amount')) | Q(status='rejected')),
                        then=F('amount') - F('approved_amount')
                    ),
                    default=Value(0),
                    output_field=DecimalField()
                )
            ),
            total_approved=Sum(
                Case(
                    When(status__in=['approved', 'payment_uploaded'], then=F('approved_amount')),
                    default=Value(0),
                    output_field=DecimalField()
                )
            ),
            total_confirmed=Sum(
                Case(
                    When(status='confirmed', then=F('approved_amount')),
                    default=Value(0),
                    output_field=DecimalField()
                )
            )
        )

        total_p = totals['total_proposal'] or 0
        total_a = totals['total_approved'] or 0
        total_c = totals['total_confirmed'] or 0

        context['total_proposal'] = total_p
        context['total_approved'] = total_a
        context['total_confirmed'] = total_c
        context['project_investmenttotals'] = total_p + total_a + total_c
        
        documents = Document.objects.filter(
            content_type=ContentType.objects.get_for_model(Deal),
            object_id=deal.id
        )
        
        # Create a mapping of document_type to document object
        doc_map = {doc.document_type: doc for doc in documents}
        
        # Build organized list: (Display Title, Document Object or None)
        organized_documents = []
        for title, slug in EXPECTED_TITLES:
            organized_documents.append({
                'title': title,
                'document': doc_map.get(slug)
            })
            
        context['organized_documents'] = organized_documents
        context['documents'] = documents  # Keep original for backward compatibility if needed

        
        # Internal Notes
        context['internal_notes'] = deal.internal_notes_list.all().select_related('user').order_by('created_at')
        context['note_form'] = DealInternalNoteForm()
        
        if (user.is_partner or user.is_admin) and deal.workflow_status == 'draft':
            # Check if THIS user has already approved
            context['has_approved'] = deal.approvals.filter(id=user.id).exists()
            
            # Count remaining
            total_needed = User.objects.filter(role__in=['admin', 'partner'], is_active=True).count()
            current = deal.approvals.count()
            context['approval_progress'] = f"{current}/{total_needed}"
        
        return context

    def post(self, request, *args, **kwargs):
        """Handle adding a new internal note"""
        self.object = self.get_object()
        form = DealInternalNoteForm(request.POST)
        if form.is_valid():
            note = form.save(commit=False)
            note.deal = self.object
            note.user = request.user
            note.save()            

            deal = self.object
            deal.workflow_status = 'review'
            deal.save()

            messages.success(request, 'Internal note added successfully.')
            return redirect('investors:deal_detail', pk=self.object.pk)
        
        # If form is invalid, re-render with context
        context = self.get_context_data(object=self.object)
        context['note_form'] = form
        return self.render_to_response(context)

class DealCreateView(LoginRequiredMixin, CreateView):
    model = Deal
    form_class = DealForm
    template_name = 'investors/deal_form.html'
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def get_success_url(self):
        """
        After creating a deal, redirect immediately to the Send Invitation page.
        """
        # return reverse_lazy('investors:deal_send', kwargs={'pk': self.object.pk})
        return reverse_lazy('investors:deal_detail', kwargs={'pk': self.object.pk})
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        saved_deal = form.save()
        
        # 1. Auto-add the Creator's approval (since they made it)
        # saved_deal.approvals.add(self.request.user)
        
        # 2. Check if Creator is the ONLY partner (auto-publish if so)
        saved_deal.check_approval_status()
        
        # Handle document uploads
        deal_content_type = ContentType.objects.get_for_model(Deal)
        
        def save_deal_doc(field_name, doc_type, title_suffix):
            file_data = form.cleaned_data.get(field_name)
            if file_data:
                Document.objects.create(
                    content_type=deal_content_type,
                    object_id=saved_deal.id,
                    document_type=doc_type,
                    title=f'{title_suffix} - {saved_deal.company_name}',
                    file=file_data,
                    description=f'{title_suffix} uploaded during deal creation',
                    uploaded_by=self.request.user
                )
        
        # 1. Pitch Deck & Financials (Existing)
        save_deal_doc('pitch_deck', 'pitch_deck', 'Pitch Deck')
        save_deal_doc('financials', 'financials', 'Financials')
        
        # 2. New Document Types (Added based on Source 116/226)
        save_deal_doc('write_up', 'write_up', 'Write Up')
        save_deal_doc('one_pager', 'one_pager', 'One Pager')
        save_deal_doc('term_sheet', 'term_sheet', 'Term Sheet')
        save_deal_doc('projections', 'projections', 'Projections')
        
        messages.success(self.request, 'Deal created as DRAFT. Under approval.')
        return super().form_valid(form)

class DealUpdateView(LoginRequiredMixin, UpdateView):
    model = Deal
    form_class = DealForm
    template_name = 'investors/deal_form.html'
    success_url = reverse_lazy('investors:deal_list')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def form_valid(self, form):
        if (self.request.user.is_partner or self.request.user.is_admin):
            form.instance.workflow_status = 'review'
        else:
            form.instance.workflow_status = 'draft'   
        form.instance.save()
        saved_deal = form.save()
        # Save internal note if provided during update
        update_note = self.request.POST.get('update_note_text')
        if update_note:
            DealInternalNote.objects.create(
                deal=saved_deal,
                user=self.request.user,
                remark=update_note
            )
        # Handle document uploads (only if new files are provided)
        deal_content_type = ContentType.objects.get_for_model(Deal)
        
        def save_deal_doc(field_name, doc_type, title_suffix):
            file_data = form.cleaned_data.get(field_name)
            # Only create new document if a new file is actually uploaded
            if file_data:
                Document.objects.create(
                    content_type=deal_content_type,
                    object_id=saved_deal.id,
                    document_type=doc_type,
                    title=f'{title_suffix} - {saved_deal.company_name}',
                    file=file_data,
                    description=f'{title_suffix} updated during deal edit',
                    uploaded_by=self.request.user
                )
        
        # 1. Pitch Deck & Financials
        save_deal_doc('pitch_deck', 'pitch_deck', 'Pitch Deck')
        save_deal_doc('financials', 'financials', 'Financials')
        
        # 2. New Document Types
        save_deal_doc('write_up', 'write_up', 'Write Up')
        save_deal_doc('one_pager', 'one_pager', 'One Pager')
        save_deal_doc('term_sheet', 'term_sheet', 'Term Sheet')
        save_deal_doc('projections', 'projections', 'Projections')
        
        messages.success(self.request, 'Deal updated successfully.')
        return super().form_valid(form)

class DealDeleteView(AdminRequiredMixin, SuccessMessageMixin, DeleteView):
    model = Deal
    template_name = 'investors/deal_confirm_delete.html'
    success_url = reverse_lazy('investors:deal_list')
    
    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'Deal deleted successfully.')
        return super().delete(request, *args, **kwargs)
    
# Commitment Views
class CommitmentListView(LoginRequiredMixin, ListView):
    model = Commitment
    template_name = 'investors/commitment_list.html'
    context_object_name = 'commitments'
    paginate_by = 20
    
    def get_queryset(self):
        user = self.request.user
        qs = Commitment.objects.all()
        
        # Filter by investor/deal if provided
        investor_id = self.request.GET.get('investor')
        deal_id = self.request.GET.get('deal')
        
        if investor_id:
            qs = qs.filter(investor_id = investor_id)
        if deal_id:
            qs = qs.filter(deal_id = deal_id)
        
        # Team members only see commitments for their assigned investors
        if user.is_team_member:
            investor_ids = Investor.objects.filter(created_by = user).values_list('id', flat = True)
            qs = qs.filter(investor_id__in = investor_ids)
        
        return qs.select_related('investor', 'deal')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        queryset = self.get_queryset()
        totals = queryset.aggregate(
            total_proposal=Sum(
                Case(
                    When(
                        Q(status__in=['pending', 'rejected', 'committed', 'payment_uploaded']) & 
                        (~Q(amount=F('approved_amount')) | Q(status='rejected')),
                        then=F('amount') - F('approved_amount')
                    ),
                    default=Value(0),
                    output_field=DecimalField()
                )
            ),
            total_approved=Sum(
                Case(
                    When(status__in=['approved', 'payment_uploaded'], then=F('approved_amount')),
                    default=Value(0),
                    output_field=DecimalField()
                )
            ),
            total_confirmed=Sum(
                Case(
                    When(status='confirmed', then=F('approved_amount')),
                    default=Value(0),
                    output_field=DecimalField()
                )
            )
        )

        total_p = totals['total_proposal'] or 0
        total_a = totals['total_approved'] or 0
        total_c = totals['total_confirmed'] or 0

        context['total_proposal'] = total_p
        context['total_approved'] = total_a
        context['total_confirmed'] = total_c
        context['project_investmenttotals'] = total_p + total_a + total_c
        
        return context

class CommitmentCreateView(LoginRequiredMixin, CreateView):
    model = Commitment
    form_class = CommitmentForm
    template_name = 'investors/commitment_form.html'
    success_url = reverse_lazy('investors:commitment_list')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs() 
        kwargs['user'] = self.request.user    
        return kwargs
    
    def get_initial(self):
        initial = super().get_initial()
        initial['status'] = 'committed'
        initial['created_by'] = self.request.user
        return initial
    
    def form_valid(self, form):
        commitment = form.instance
        investor = form.cleaned_data["investor"]
        deal = form.cleaned_data['deal']
        commitment.status = 'committed'
        commitment.save()
        
        email_sent, error_msg = send_payment_request(self.request, commitment)            
        if email_sent:
            form.instance.approved_amount = commitment.approved_amount
            form.instance.status = 'approved'
            form.save()
            messages.success(self.request, f"Commitment approved! Payment request sent to {commitment.investor.full_name}.")
        else:
            messages.warning(self.request, f"Commitment approved, but email failed: {error_msg}")
            form.instance.status = 'committed'
            form.save()
            
        return redirect(self.success_url)     

    def form_invalid(self, form):
        messages.warning(self.request, 'Investor already has a commitment for this deal.')
        return redirect(self.success_url)

class CommitmentUpdateView(LoginRequiredMixin, UpdateView):
    model = Commitment
    form_class = CommitmentForm
    template_name = 'investors/commitment_form.html'
    success_url = reverse_lazy('investors:commitment_list')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        pk = form.instance.id    
        commitment = get_object_or_404(Commitment, pk = pk)
        commitment_status = form.instance.status    
        messages.success(self.request, 'Commitment updated successfully.')       
        action = self.request.POST.get("action")
        
        if commitment_status in ['committed']:
            if form.instance.approved_amount == 0.00:
               commitment.approved_amount = commitment.amount
               commitment.save() 
            else:   
               commitment.approved_amount = form.cleaned_data['approved_amount']
               commitment.save()

            email_sent, error_msg = send_payment_request(self.request, commitment)            
            if email_sent:
                form.instance.approved_amount = commitment.approved_amount
                form.instance.status = 'approved'
                form.save()
                messages.success(self.request, f"Commitment approved! Payment request sent to {commitment.investor.full_name}.")
            else:
                messages.warning(self.request, f"Commitment approved, but email failed: {error_msg}")   
        
        if commitment_status in ['approved']:
            form.instance.status = 'payment_uploaded'
            form.save()
            messages.success(self.request, f"Payment uploaded!.")

        action = self.request.POST.get("action")
        if commitment_status in ['payment_uploaded'] and action == 'confirm':
            commitment.status = 'confirmed'
            commitment.save()
            success, msg = send_confirmation_email(self.request, commitment)       
            # 3. User Feedback
            if success:
                form.instance.status = 'confirmed'
                form.save()
                messages.success(self.request, f"Payment verified! Confirmation email sent to {commitment.investor.full_name}.")
            else:
                messages.warning(self.request, f"Payment verified, but email failed: {msg}")
        
        elif commitment_status in ['payment_uploaded'] and action == 'reject':
            commitment.status = 'rejected'
            commitment.save()
            success, msg = send_rejected_email(self.request, commitment)
            if success:
                form.instance.status = 'rejected'
                form.save()
                messages.success(self.request, f"Commitment Rejected! Confirmation email sent to {commitment.investor.full_name}.")
            else:
                messages.warning(self.request, f"Commitment Rejected, but email failed: {msg}")
            pass 

        return super().form_valid(form)

class CommitmentDeleteView(LoginRequiredMixin, DeleteView):
    model = Commitment
    template_name = 'investors/commitment_confirm_delete.html'
    success_url = reverse_lazy('investors:commitment_list')
    
    def delete(self, request, *args, **kwargs):        
        messages.success(self.request, 'Commitment deleted successfully.')
        return super().delete(request, *args, **kwargs)

def external_investor_form(request, token):
    """
    External investor form view that accepts a UUID token.
    No login required - public-facing form for investors to update their details.
    """
    # Validate token format
    if not request.session.get(f'auth_{str(token)}'):
        request.session['next_url'] = request.path
        return redirect('investors:external_investor_form', token=token)
    
    # try:
    #     token_uuid = uuid.UUID(str(token))
    # except (ValueError, TypeError):
    #     return render(request, 'investors/external_form_error.html', {
    #         'error_title': 'Invalid Link',
    #         'error_message': 'The provided link is invalid. Please contact support for assistance.'
    #     }, status=400)
    
    
    # Get secure link
    try:
        secure_link = get_object_or_404(SecureLink, token=token)
    except SecureLink.DoesNotExist:
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Link Not Found',
            'error_message': 'The provided link does not exist. Please contact support for assistance.'
        }, status=404)
    
    # Check if link is valid (active and not expired)
    if not secure_link.is_valid():
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Link Expired',
            'error_message': 'This link has expired or been deactivated. Please contact support for a new link.'
        }, status=403)
    
    investor = secure_link.investor
    
    # Handle form submission
    if request.method == 'POST':
        form = ExternalInvestorForm(request.POST, request.FILES, instance=investor)
        if form.is_valid():
            # Save investor details
            form.save()
            
            # Handle document uploads
            investor_content_type = ContentType.objects.get_for_model(Investor)
            
            # Upload PAN document
            if form.cleaned_data.get('pan_document'):
                Document.objects.create(
                    content_type=investor_content_type,
                    object_id=investor.id,
                    document_type='kyc',
                    title=f'PAN Card - {investor.full_name}',
                    file=form.cleaned_data['pan_document'],
                    description='PAN Card document uploaded by investor via secure link'
                )
            
            # Upload Aadhaar document
            if form.cleaned_data.get('aadhaar_document'):
                Document.objects.create(
                    content_type=investor_content_type,
                    object_id=investor.id,
                    document_type='kyc',
                    title=f'Aadhaar Card - {investor.full_name}',
                    file=form.cleaned_data['aadhaar_document'],
                    description='Aadhaar Card document uploaded by investor via secure link'
                )
            
            # Upload bank statement
            if form.cleaned_data.get('bank_statement'):
                Document.objects.create(
                    content_type=investor_content_type,
                    object_id=investor.id,
                    document_type='bank',
                    title=f'Bank Statement - {investor.full_name}',
                    file=form.cleaned_data['bank_statement'],
                    description='Bank Statement uploaded by investor via secure link'
                )
            
            # Invalidate the token by deactivating it
            secure_link.is_active = False
            secure_link.save()
            
            # Show success message
            return render(request, 'investors/external_form_success.html', {
                'investor_name': investor.full_name
            })
    else:
        # GET request - show form
        form = ExternalInvestorForm(instance=investor)
        # Track access
        secure_link.increment_access()
    
    return render(request, 'investors/external_form.html', {
        'form': form,
        'investor': investor,
        'secure_link': secure_link
    })

def deal_interest_view(request, token, deal_id):
    """
    Public deal interest view accessible via secure link.
    Allows investors to express interest, not interested, or commit amount for a deal.
    """
    
    #if not request.session.get(f'auth_{str(token)}'):
    #    request.session['next_url'] = request.path
    #    return redirect('investors:external_access_otp', token=token)
    
    try:
        secure_link = get_object_or_404(SecureLink, token=token)
    except SecureLink.DoesNotExist:
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Link Not Found',
            'error_message': 'The provided link does not exist. Please contact support for assistance.'
        }, status=404)
    
    # Check if link is valid
    if not secure_link.is_valid():
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Link Expired',
            'error_message': 'This link has expired or been deactivated. Please contact support for a new link.'
        }, status=403)
    
    investor = secure_link.investor
    
    # Get deal
    try:
        deal = get_object_or_404(Deal, pk=deal_id)
    except Deal.DoesNotExist:
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Deal Not Found',
            'error_message': 'The requested deal does not exist.'
        }, status=404)
    
    # Get existing commitment if any
    existing_commitment = Commitment.objects.filter(investor=investor, deal=deal).first()
    
    # Handle form submission
    if request.method == 'POST':
        form = DealInterestForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            action = data['action']            
            if action == 'not_interested':
                status = 'not_committed'
                Commitment.objects.update_or_create(
                    investor=investor, deal=deal,
                    defaults={
                        'status': status,
                        'amount': 0,
                        'payment_timeline': None,
                        'payment_timeline_type': None,
                        'meeting_requested': False,
                        'questions': '',
                        'not_interested_remark': data.get('not_interested_remark') if data.get('not_interested_remark') else None
                    }
                )
                commitment = Commitment.objects.filter(investor=investor, deal=deal).first()
                send_thankyou_email_not_committed(request, commitment, sender_user=secure_link.created_by)

            else:
                # Handle 'committed' or 'interested'
                status = 'committed' if action == 'commit' else 'interested'
                Commitment.objects.update_or_create(
                    investor=investor, deal=deal,
                    defaults={
                        'status': status,
                        'amount': data.get('committed_amount') or 0,
                        'payment_timeline': data.get('payment_timeline'),
                        'payment_timeline_type': data.get('payment_timeline_type'),
                        'meeting_requested': data.get('request_meeting', False),
                        'questions': data.get('questions', '')                        
                    }
                )
            
            secure_link.is_active = False
            secure_link.save()
            
            return render(request, 'investors/deal_interest_success.html', {
                'investor': investor,
                'investor_name': investor.full_name,
                'deal_name': deal.company_name,
                'action': data['action'],
                'not_interested_remark': data.get('not_interested_remark') if data['action'] == 'not_interested' else None,
                'amount': data.get('committed_amount') if data['action'] == 'commit' else None,
                'payment_timeline': data.get('payment_timeline') if data['action'] == 'commit' else None,   
                'payment_timeline_type': data.get('payment_timeline_type') if data['action'] == 'commit' else None             
            })           
    else:        
        form = DealInterestForm()

    # Get deal documents
    deal_content_type = ContentType.objects.get_for_model(Deal)
    documents = Document.objects.filter(
        content_type=deal_content_type,
        object_id=deal.id
    )    
    return render(request, 'investors/deal_interest.html', {
        'form': form,
        'investor': investor,
        'deal': deal,
        'documents': documents,
        'existing_commitment': existing_commitment,
        'secure_link': secure_link
    })

@login_required
def deal_dashboard(request, deal_id):
    """
    Deal Dashboard view showing all interested investors and their status.
    Shows: Pending, Partially Paid, Fully Paid based on commitment status.
    """
    try:
        deal = Deal.objects.get(pk=deal_id)
    except Deal.DoesNotExist:
        messages.error(request, 'Deal not found.')
        return redirect('investors:deal_list')
    
    # Get all commitments for this deal
    commitments = Commitment.objects.filter(deal=deal).select_related('investor').order_by('-created_at')
    
    # Categorize commitments by payment status
    # For this implementation:
    # - Pending = status='interested' or status='committed'
    # - Fully Paid = status='paid'
    # Note: We don't have partial payment tracking, so we'll use 'committed' as partially paid indicator
    
    pending_commitments = commitments.filter(status__in=['interested', 'approved', 'payment_uploaded'])
    paid_commitments = commitments.filter(status='confirmed')
    
    # Calculate totals
    total_commitments = commitments.count()
    total_committed_amount = commitments.aggregate(total=Sum('amount'))['total'] or 0
    total_paid_amount = paid_commitments.aggregate(total=Sum('amount'))['total'] or 0
    total_pending_amount = pending_commitments.aggregate(total=Sum('amount'))['total'] or 0
    
    context = {
        'deal': deal,
        'commitments': commitments,
        'pending_commitments': pending_commitments,
        'paid_commitments': paid_commitments,
        'total_commitments': total_commitments,
        'total_committed_amount': total_committed_amount,
        'total_paid_amount': total_paid_amount,
        'total_pending_amount': total_pending_amount,
    }
    
    return render(request, 'investors/deal_dashboard.html', context)

class InvestorBulkUploadView(LoginRequiredMixin, FormView):
    template_name = 'investors/investor_bulk_upload.html'
    form_class = InvestorBulkUploadForm
    success_url = reverse_lazy('investors:investor_list')

    def form_valid(self, form):
        file = form.cleaned_data['file']
        
        # ... (File reading logic remains the same) ...
        try:
            if file.name.endswith('.csv'):
                df = pd.read_csv(file)
            elif file.name.endswith(('.xls', '.xlsx')):
                df = pd.read_excel(file)
            else:
                messages.error(self.request, "Invalid file format.")
                return redirect('investors:investor_bulk_upload')
        except Exception as e:
            messages.error(self.request, f"Error reading file: {str(e)}")
            return redirect('investors:investor_bulk_upload')

        # Standardize Headers
        df.columns = [str(c).strip().lower().replace(' ', '_') for c in df.columns]
        
        investor_content_type = ContentType.objects.get_for_model(Investor)

        success_count = 0
        update_count = 0
        error_count = 0
        skipped_demo_count = 0  # Track skipped demo rows

        # Define the DEMO PAN to detect
        DEMO_PAN_CHECK = 'ABCDE1234F' 

        for index, row in df.iterrows():
            try:
                # Clean PAN first
                pan = str(row['pan']).strip().upper()

                # --- LOGIC TO REMOVE EXAMPLE DATA ---
                # If the PAN matches the demo file's PAN, skip this row entirely
                if pan == DEMO_PAN_CHECK:
                    skipped_demo_count += 1
                    continue 
                # ------------------------------------

                with transaction.atomic():
                    email = str(row['email']).strip()
                    mobile = str(row['mobile']).strip()
                    
                    # Handle Date
                    dob_val = row['dob']
                    if pd.isna(dob_val):
                         dob = None
                    else:
                         dob = pd.to_datetime(dob_val).date()

                    # Handle Team Member
                    assigned_user = None
                    if 'team_member_email' in row and pd.notna(row['team_member_email']):
                        try:
                            assigned_user = User.objects.get(email=str(row['team_member_email']).strip(), role='team_member')
                        except User.DoesNotExist:
                            assigned_user = None

                    defaults = {
                        'full_name': row['full_name'],
                        'email': email,
                        'mobile': mobile,
                        'aadhaar': str(row['aadhaar']).strip(),
                        'address': row['address'],
                        'dob': dob,
                        'profession': row.get('profession', ''),
                        'bank_name': row.get('bank_name', ''),
                        'account_number': row.get('account_number', ''),
                        'ifsc_code': row.get('ifsc_code', ''),
                        'dp_id': row.get('dp_id', ''),
                        'client_id': row.get('client_id', ''),
                        'investment_capacity': row.get('investment_capacity', 0) if pd.notna(row.get('investment_capacity')) else 0,
                        'is_active': True if self.request.user.is_partner or self.request.user.is_admin else False
                    }

                    investor, created = Investor.objects.update_or_create(
                        pan=pan,
                        defaults=defaults
                    )

                    investor.save() # Trigger group logic

                    # Set created_by only on creation
                    if created:
                        investor.created_by = self.request.user

                    # Assign team member(s) after creation
                    if assigned_user:
                        investor.assigned_team_members.add(assigned_user)
                    investor.save() # Trigger group logic and save created_by
                    
                    def save_link_document(doc_type, title_prefix, link_col_name):
                        # Get the link from the current row
                        link = str(row.get(link_col_name, '')).strip()
                        
                        # Only proceed if link exists and is not 'nan'
                        if link and link.lower() != 'nan':
                            
                            # Check if document already exists
                            doc = Document.objects.filter(
                                content_type=investor_content_type,
                                object_id=investor.id,
                                document_type=doc_type,
                                title=f'{title_prefix} - {investor.full_name}'
                            ).first()
                            
                            # Prepare content for the dummy file
                            file_content = f"This document is an external link.\nClick here: {link}"
                            dummy_file = ContentFile(file_content.encode('utf-8'))
                            dummy_filename = f"{link_col_name}_{investor.id}.txt"
                            description_text = f"External Drive Link: {link}"

                            if doc:
                                # Update existing document
                                doc.description = description_text
                                doc.file.save(dummy_filename, dummy_file, save=True)
                            else:
                                # Create new document
                                new_doc = Document(
                                    content_type=investor_content_type,
                                    object_id=investor.id,
                                    document_type=doc_type,
                                    title=f'{title_prefix} - {investor.full_name}',
                                    description=description_text,
                                    uploaded_by=self.request.user
                                )
                                new_doc.file.save(dummy_filename, dummy_file, save=True)

                    # 1. Save PAN
                    save_link_document('kyc', 'PAN Card', 'pan_link')
                    
                    # 2. Save Aadhaar
                    save_link_document('kyc', 'Aadhaar Card', 'aadhaar_link')
                    
                    # 3. Save Bank Statement
                    save_link_document('bank', 'Bank Statement', 'bank_link')

                    if created:
                        success_count += 1
                    else:
                        update_count += 1

            except IntegrityError:
                traceback.print_exc()
                error_count += 1
            except Exception as e:
                traceback.print_exc()
                
                error_count += 1

        # Feedback Message
        msg = f"Processed! Created: {success_count}, Updated: {update_count}."
        if skipped_demo_count > 0:
            msg += f" (Skipped {skipped_demo_count} demo row)."
            
        if success_count > 0 or update_count > 0:
            messages.success(self.request, msg)
        
        if error_count > 0:
            messages.warning(self.request, f"Errors in {error_count} rows.")

        return super().form_valid(form)

def download_demo_file(request):
    """
    Generates a sample CSV file with added Document Link columns.
    """
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="investor_upload_template.csv"'

    writer = csv.writer(response)
    
    # 1. Update Headers to include Link columns
    headers = [
        'full_name', 'email', 'mobile', 'pan', 'aadhaar', 'dob', 
        'address', 'investment_capacity', 'profession', 
        'bank_name', 'account_number', 'ifsc_code', 'team_member_email',
        'pan_link', 'aadhaar_link', 'bank_link'  # <--- NEW COLUMNS
    ]
    writer.writerow(headers)

    # 2. Update Example Row
    example_row = [
        'John Doe (Demo User)',      
        'demo_user@example.com',     
        '9876543210',                
        'ABCDE1234F',               
        '123456789012',              
        '1990-01-01',                
        '123 Demo Street, Mumbai',   
        '5000000',                   
        'Business',                  
        'HDFC Bank',                 
        '50100012345678',            
        'HDFC0001234',               
        'agent@example.com',
        'https://drive.google.com/file/d/example-pan',     # pan_link
        'https://drive.google.com/file/d/example-aadhaar', # aadhaar_link
        'https://drive.google.com/file/d/example-bank'     # bank_link
    ]
    writer.writerow(example_row)

    return response

@login_required
def approve_deal(request, pk):
    deal = get_object_or_404(Deal, pk=pk)
    
    # Security check
    #if not (request.user.is_partner or request.user.is_admin):
    #    messages.error(request, "Permission denied.")
    #    return redirect('investors:dashboard')
        
    # Add user to approvals
    deal.approvals.add(request.user)
    
    # Run the check logic
    deal.check_approval_status()
    
    messages.success(request, f"You have approved {deal.company_name}.")
    
    if deal.workflow_status == 'approved':
        messages.success(request, "Deal is now LIVE (All partners approved).")
        
    return redirect('investors:deal_detail', pk=pk)

@login_required
def email_editor(request, pk=None): 
    # Get the key email template (singleton pattern for now as per URL config)     
    existing_template_title = request.GET.get('existing_template') or request.POST.get('existing_template_hidden')
    
    instance = None
    if existing_template_title and existing_template_title != 'other':
        instance = MyModel.objects.filter(title=existing_template_title).first()

    if request.method == "GET":
        if existing_template_title == 'other':
            form = MyModelForm()
            form.fields['existing_template'].initial = 'other'
        elif instance:
            form = MyModelForm(instance=instance)
            form.fields['existing_template'].initial = existing_template_title
        else:
            form = MyModelForm()                       
    elif request.method == "POST":
        if 'delete' in request.POST:
            if instance:
               instance.delete()
               messages.success(request, "Email template deleted successfully.")
            return redirect('investors:emails_templates')
        else:                           
            form = MyModelForm(request.POST, instance=instance)             
            # If creating new, ensure title is provided and unique-ish logic
            if request.POST.get('existing_template') == 'other':
               form.fields['title'].required = True
            else:
               form.fields['title'].required = False
            
            if form.is_valid():    
               obj = form.save(commit=False)
               obj.save() 
               messages.success(request, "Email template saved successfully.")
               return redirect(f"{reverse('investors:emails_templates')}?existing_template={obj.title}")
            else:
               messages.error(request, "Please correct the errors below.")    

    return render(request, "investors/emails_templates.html", {"form": form})