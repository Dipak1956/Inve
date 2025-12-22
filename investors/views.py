from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.db.models import Q, Sum
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
import uuid

from .models import User, Investor, Deal, Commitment, Document, SecureLink
from .mixins import RoleRequiredMixin, PartnerRequiredMixin, AdminRequiredMixin, TeamMemberAccessMixin
from .decorators import role_required, partner_required, admin_required
from .forms import InvestorForm, ExternalInvestorForm, DealForm, DealInterestForm


def is_admin_or_partner(user):
    """Test function for user_passes_test decorator"""
    return user.is_authenticated and (user.is_admin or user.is_partner)


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
        
        # Status statistics for deals
        new_deals = Deal.objects.filter(status='new').count()
        active_deals = Deal.objects.filter(status='active').count()
        closing_deals = Deal.objects.filter(status='closing').count()
        closed_deals = Deal.objects.filter(status='closed').count()
        
        # Recent investors (all)
        recent_investors = Investor.objects.select_related('assigned_team_member').all()[:5]
    else:
        # Team Member: Show ONLY assigned investors
        assigned_investors = Investor.objects.filter(assigned_team_member=user)
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
        
        # Status statistics for deals (all deals visible)
        new_deals = Deal.objects.filter(status='new').count()
        active_deals = Deal.objects.filter(status='active').count()
        closing_deals = Deal.objects.filter(status='closing').count()
        closed_deals = Deal.objects.filter(status='closed').count()
        
        # Recent investors (only assigned)
        recent_investors = assigned_investors.select_related('assigned_team_member').all()[:5]
    
    # Recent deals (all users see all deals)
    recent_deals = Deal.objects.select_related('created_by').all()[:5]
    
    # Recent commitments based on user role
    if user.is_admin or user.is_partner:
        recent_commitments = Commitment.objects.select_related('investor', 'deal').all()[:5]
    else:
        investor_ids = Investor.objects.filter(assigned_team_member=user).values_list('id', flat=True)
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
    
    def get_queryset(self):
        user = self.request.user
        # Filter by user role: Team members only see assigned investors
        if user.is_team_member:
            qs = Investor.objects.filter(assigned_team_member=user)
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
        
        # Apply group filter
        group_filter = self.request.GET.get('group', '')
        if group_filter:
            qs = qs.filter(group=group_filter)
        
        # Apply team member filter (Admin/Partner only)
        if not user.is_team_member:
            team_member_filter = self.request.GET.get('team_member', '')
            if team_member_filter:
                qs = qs.filter(assigned_team_member_id=team_member_filter)
        
        return qs.select_related('assigned_team_member', 'family_head')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Add filter options for admin/partner
        if not user.is_team_member:
            context['team_members'] = User.objects.filter(role='team_member')
        
        return context


class InvestorDetailView(TeamMemberAccessMixin, DetailView):
    model = Investor
    template_name = 'investors/investor_detail.html'
    context_object_name = 'investor'
    
    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if user.is_team_member:
            # Check if investor is assigned to this team member
            investor = qs.filter(id=self.kwargs['pk']).first()
            if investor and investor.assigned_team_member != user:
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


class InvestorCreateView(PartnerRequiredMixin, CreateView):
    model = Investor
    form_class = InvestorForm
    template_name = 'investors/investor_form.html'
    success_url = reverse_lazy('investors:investor_list')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def form_valid(self, form):
        # If user is a team member, ensure the investor is assigned to them
        if self.request.user.is_team_member:
            form.instance.assigned_team_member = self.request.user
        messages.success(self.request, 'Investor created successfully.')
        return super().form_valid(form)


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
        return Investor.objects.filter(assigned_team_member=user)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def form_valid(self, form):
        messages.success(self.request, 'Investor updated successfully.')
        return super().form_valid(form)


class InvestorDeleteView(AdminRequiredMixin, DeleteView):
    model = Investor
    template_name = 'investors/investor_confirm_delete.html'
    success_url = reverse_lazy('investor_list')
    
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
        
        return qs


class DealDetailView(LoginRequiredMixin, DetailView):
    model = Deal
    template_name = 'investors/deal_detail.html'
    context_object_name = 'deal'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        deal = self.get_object()
        context['commitments'] = Commitment.objects.filter(deal=deal)
        context['total_commitments'] = Commitment.objects.filter(
            deal=deal
        ).aggregate(total=Sum('amount'))['total'] or 0
        context['documents'] = Document.objects.filter(
            content_type=ContentType.objects.get_for_model(Deal),
            object_id=deal.id
        )
        return context


class DealCreateView(PartnerRequiredMixin, CreateView):
    model = Deal
    form_class = DealForm
    template_name = 'investors/deal_form.html'
    success_url = reverse_lazy('investors:deal_list')
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        saved_deal = form.save()
        
        # Handle document uploads
        deal_content_type = ContentType.objects.get_for_model(Deal)
        
        # Upload Pitch Deck
        if form.cleaned_data.get('pitch_deck'):
            Document.objects.create(
                content_type=deal_content_type,
                object_id=saved_deal.id,
                document_type='pitch_deck',
                title=f'Pitch Deck - {saved_deal.company_name}',
                file=form.cleaned_data['pitch_deck'],
                description='Pitch Deck uploaded during deal creation',
                uploaded_by=self.request.user
            )
        
        # Upload Financials
        if form.cleaned_data.get('financials'):
            Document.objects.create(
                content_type=deal_content_type,
                object_id=saved_deal.id,
                document_type='financials',
                title=f'Financials - {saved_deal.company_name}',
                file=form.cleaned_data['financials'],
                description='Financials uploaded during deal creation',
                uploaded_by=self.request.user
            )
        
        messages.success(self.request, 'Deal created successfully.')
        return super().form_valid(form)


class DealUpdateView(PartnerRequiredMixin, UpdateView):
    model = Deal
    form_class = DealForm
    template_name = 'investors/deal_form.html'
    success_url = reverse_lazy('investors:deal_list')
    
    def form_valid(self, form):
        saved_deal = form.save()
        
        # Handle document uploads (only if new files are provided)
        deal_content_type = ContentType.objects.get_for_model(Deal)
        
        # Upload Pitch Deck (if new file provided)
        if form.cleaned_data.get('pitch_deck'):
            Document.objects.create(
                content_type=deal_content_type,
                object_id=saved_deal.id,
                document_type='pitch_deck',
                title=f'Pitch Deck - {saved_deal.company_name}',
                file=form.cleaned_data['pitch_deck'],
                description='Pitch Deck uploaded during deal update',
                uploaded_by=self.request.user
            )
        
        # Upload Financials (if new file provided)
        if form.cleaned_data.get('financials'):
            Document.objects.create(
                content_type=deal_content_type,
                object_id=saved_deal.id,
                document_type='financials',
                title=f'Financials - {saved_deal.company_name}',
                file=form.cleaned_data['financials'],
                description='Financials uploaded during deal update',
                uploaded_by=self.request.user
            )
        
        messages.success(self.request, 'Deal updated successfully.')
        return super().form_valid(form)


class DealDeleteView(AdminRequiredMixin, DeleteView):
    model = Deal
    template_name = 'investors/deal_confirm_delete.html'
    success_url = reverse_lazy('deal_list')
    
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
            qs = qs.filter(investor_id=investor_id)
        if deal_id:
            qs = qs.filter(deal_id=deal_id)
        
        # Team members only see commitments for their assigned investors
        if user.is_team_member:
            investor_ids = Investor.objects.filter(
                assigned_team_member=user
            ).values_list('id', flat=True)
            qs = qs.filter(investor_id__in=investor_ids)
        
        return qs.select_related('investor', 'deal')


class CommitmentCreateView(PartnerRequiredMixin, CreateView):
    model = Commitment
    template_name = 'investors/commitment_form.html'
    fields = ['investor', 'deal', 'amount', 'status', 'payment_proof']
    success_url = reverse_lazy('commitment_list')
    
    def form_valid(self, form):
        messages.success(self.request, 'Commitment created successfully.')
        return super().form_valid(form)


class CommitmentUpdateView(PartnerRequiredMixin, UpdateView):
    model = Commitment
    template_name = 'investors/commitment_form.html'
    fields = ['investor', 'deal', 'amount', 'status', 'payment_proof']
    success_url = reverse_lazy('commitment_list')
    
    def form_valid(self, form):
        messages.success(self.request, 'Commitment updated successfully.')
        return super().form_valid(form)


class CommitmentDeleteView(AdminRequiredMixin, DeleteView):
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
    try:
        token_uuid = uuid.UUID(str(token))
    except (ValueError, TypeError):
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Invalid Link',
            'error_message': 'The provided link is invalid. Please contact support for assistance.'
        }, status=400)
    
    # Get secure link
    try:
        secure_link = SecureLink.objects.get(token=token_uuid)
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
    # Validate token
    try:
        token_uuid = uuid.UUID(str(token))
    except (ValueError, TypeError):
        return render(request, 'investors/external_form_error.html', {
            'error_title': 'Invalid Link',
            'error_message': 'The provided link is invalid. Please contact support for assistance.'
        }, status=400)
    
    # Get secure link
    try:
        secure_link = SecureLink.objects.get(token=token_uuid)
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
        deal = Deal.objects.get(pk=deal_id)
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
            action = form.cleaned_data['action']
            committed_amount = form.cleaned_data.get('committed_amount', 0)
            
            if action == 'not_interested':
                # Delete commitment if exists
                if existing_commitment:
                    existing_commitment.delete()
                return render(request, 'investors/deal_interest_success.html', {
                    'investor': investor,
                    'investor_name': investor.full_name,
                    'deal_name': deal.company_name,
                    'action': 'not_interested'
                })
            else:
                # Create or update commitment
                status = 'committed' if action == 'commit' else 'interested'
                amount = committed_amount if action == 'commit' else (existing_commitment.amount if existing_commitment else deal.ticket_size)
                
                if existing_commitment:
                    existing_commitment.status = status
                    existing_commitment.amount = amount
                    existing_commitment.save()
                else:
                    Commitment.objects.create(
                        investor=investor,
                        deal=deal,
                        amount=amount,
                        status=status
                    )
                
                return render(request, 'investors/deal_interest_success.html', {
                    'investor': investor,
                    'investor_name': investor.full_name,
                    'deal_name': deal.company_name,
                    'action': action,
                    'amount': amount if action == 'commit' else None
                })
    else:
        # GET request - show form
        form = DealInterestForm()
        # Pre-fill existing commitment if any
        if existing_commitment:
            if existing_commitment.status == 'committed':
                form.fields['action'].initial = 'commit'
                form.fields['committed_amount'].initial = existing_commitment.amount
            else:
                form.fields['action'].initial = 'interested'
        # Track access
        secure_link.increment_access()
    
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
    
    pending_commitments = commitments.filter(status__in=['interested', 'committed'])
    paid_commitments = commitments.filter(status='paid')
    
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
