from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
from django.urls import reverse
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from decimal import Decimal
import uuid
import random
from ckeditor.fields import RichTextField

class User(AbstractUser):
    """
    Custom User model with role-based access control.
    Roles: Admin, Partner, Team Member
    """
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('partner', 'Partner'),
        ('team_member', 'Team Member'),
    ]
    
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='team_member',
        help_text="User role for access control"
    )
    created_by = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='created_users',
        help_text="The Admin or Partner who created this user."
    )
    # ADD THESE NEW FIELDS
    smtp_email = models.EmailField(
        blank=True, 
        null=True, 
        help_text="The Gmail address used to send invites."
    )
    smtp_password = models.CharField(
        max_length=255, 
        blank=True, 
        null=True, 
        help_text="The 16-character App Password generated from Google Account Security."
    )
    
    @property
    def is_admin(self):
        return self.role == 'admin' or self.is_superuser
    
    @property
    def is_partner(self):
        return self.role == 'partner' or self.is_admin
    
    @property
    def is_team_member(self):
        return self.role == 'team_member'
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

class Investor(models.Model):
    """
    Investor model with all required fields including KYC information.
    """
    GROUP_CHOICES = [
        ('Less_25L', 'Less_25L'),
        ('25L', '25L'),
        ('50L', '50L'),
        ('75L', '75L'),
        ('1CR', '1CR'),
        ('1.5CR', '1.5CR'),
        ('2CR', '2CR'),
        ('2.5CR', '2.5CR'),
        ('3CR', '3CR'),
        ('3.5CR', '3.5CR'),
        ('4CR', '4CR'),
        ('4.5CR', '4.5CR'),
        ('5CR', '5CR'),
        ('Above_5CR', 'Above_5CR'),
    ]
    
    RISK_APPETITE_CHOICES = [
        ('low', 'Conservative - Low Return '),
        ('medium', 'Balanced - Medium Return'),
        ('high', 'Aggressive - High Return'),
        ('fixed', 'Fix Return'),
    ]
    DURATION_CHOICES = [
        ('short', 'Short Term (< 1 Year)'),
        ('medium', 'Medium Term (1-3 Years)'),
        ('long', 'Long Term (> 3 Years)'),
        ('any', 'Any')
    ]
    TICKET_SIZE_CHOICES = [
        ('Less_25L', 'Less then 25L'),
        ('25L_1CR', '25L - 1CR'),
        ('1CR_3CR', '1CR - 3CR'),
        ('3CR', 'Above 3CR'),
    ]

    INDUSTRY_CHOICES = [
        ('Technology', 'Technology'),
        ('Healthcare', 'Healthcare'),
        ('Finance', 'Finance'),
        ('Real Estate', 'Real Estate'),
        ('Consumer Goods', 'Consumer Goods'),
        ('Energy', 'Energy'),
        ('Others', 'Others')
    ]
    
    # investor_code = models.CharField(
    #     max_length=20, 
    #     unique=True, 
    #     editable=False, 
    #     help_text="Unique auto-generated investor ID"
    # )
    
    # Basic Information
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    mobile = models.CharField(
        max_length=15,
        unique=True,
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',            
            message="Mobile number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        )]
    )
    address = models.TextField(null=True, blank=True)
    
    profession = models.CharField(
        max_length=100, 
        blank=True, 
        help_text="Profession/Nature of Income",
        null=True
    )
    
    # KYC Information
    pan = models.CharField(max_length=10, unique=True, help_text="PAN Card Number", blank=True, null=True)
    aadhaar = models.CharField(max_length=12, unique=True, help_text="Aadhaar Number (will be masked in display)", blank=True, null=True)
    dob = models.DateField(verbose_name="Date of Birth", blank=True, null=True)
    
    # Bank Details (New)
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    account_number = models.CharField(max_length=50, blank=True, null=True)
    ifsc_code = models.CharField(max_length=20, blank=True, null=True)
    dp_id = models.CharField(max_length=50, blank=True, verbose_name="DP ID", null=True)
    client_id = models.CharField(max_length=50, blank=True, verbose_name="Client ID", null=True)
    
    # --- Investment Philosophy [Source 78-84] ---
    risk_appetite = models.CharField(max_length=20, choices=RISK_APPETITE_CHOICES, blank=True, null=True)
    preferred_duration = models.CharField(max_length=20, choices=DURATION_CHOICES, blank=True, null=True)
    ticket_size_preference = models.CharField(max_length=20, choices=TICKET_SIZE_CHOICES, blank=True, null=True)
    preferred_industries = models.JSONField(blank=True, null=True, help_text="List of preferred industries")
    
    # Investment Capacity (used for automatic group assignment)
    investment_capacity = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Investment capacity in INR (used to automatically assign Group A/B)"
    )
    
    # Classification (automatically assigned based on investment_capacity)
    group = models.CharField(
        max_length=10,
        choices=GROUP_CHOICES,
        default='C',
        blank=True,
        null=True,
        help_text="Group A for investments >1Cr, Group B for ≤1Cr (auto-assigned based on investment_capacity)"
    )
    
    # Relationships
    assigned_team_members = models.ManyToManyField(
        User,
        blank=True,
        related_name='assigned_investors',
        limit_choices_to={'role': 'team_member'},
        help_text="Team members assigned to manage this investor"
    )    
    family_head = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='family_members',
        help_text="Family head for family grouping"
    )
    # Status
    is_active = models.BooleanField(default=False, help_text="Active after Partner confirmation")
    
    referred_by = models.CharField(
        max_length=255, 
        blank=True, 
        help_text="Name of the person or entity who referred this investor",
        null=True,
    )    
    remark = models.TextField(
            blank=True, 
            help_text="Internal remarks or notes about this investor",
            null=True,
        )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_investors')    

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)          
    
    def save(self, *args, **kwargs):        
        """
        Automatically assign Group A or Group B based on investment_capacity.
        Group A: investment_capacity > 1,00,00,000 (1 Crore)
        Group B: investment_capacity ≤ 1,00,00,000 (1 Crore)
        """
        """
        if self.investment_capacity is not None:
            # 1 Crore = 1,00,00,000 = 10000000
            one_crore = Decimal('10000000')
            if self.investment_capacity > one_crore:
                self.group = 'A'
            else:
                self.group = 'B'                
        """
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.full_name} ({self.email})"
    
    def get_masked_aadhaar(self):
        """Returns masked Aadhaar number for display (first 4 and last 4 visible)"""
        if self.aadhaar and len(self.aadhaar) >= 8:
            return f"{self.aadhaar[:4]}****{self.aadhaar[-4:]}"
        return "****"
    
    def get_absolute_url(self):
        return reverse('investor_detail', kwargs={'pk': self.pk})
    
    class Meta:
        verbose_name = "Investor"
        verbose_name_plural = "Investors"
        ordering = ['-created_at'] 

class Deal(models.Model):
    """
    Deal model representing investment opportunities.
    """
    STATUS_CHOICES = [
        ('new', 'New'),
        ('active', 'Active'),
        ('closing_soon', 'Closing Soon'),  # Added
        ('filled', 'Filled'),              # Added
        ('closed', 'Closed'),
    ]
    
    WORKFLOW_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('review', 'Review'),
        ('approved', 'Approved'),
    ]
    
    CATEGORY_CHOICES = [
        ('pre_ipo', 'Pre-IPO'),
        ('ipo_anchor', 'IPO - Anchor'),
        ('private_round', 'Private Round'),
        ('fundraising', 'Fundraising'),
        ('others', 'Others'),
    ]
    
    # Basic Information
    company_name = models.CharField(max_length=255)
    
    category = models.CharField(
        max_length=50, 
        choices=CATEGORY_CHOICES, 
        default='others',
        help_text="Categorization of the deal (e.g., Pre-IPO, Anchor)"
    )
    
    description = models.TextField()
    
    video_url = models.URLField(
        blank=True, 
        null=True, 
        help_text="Link to Corporate Video (if applicable)"
    )
    
    # Deal Details
    deal_size = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        help_text="Total deal size in INR"
    )
    ticket_size = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        help_text="Minimum ticket size in INR"
    )
    round_no = models.PositiveIntegerField(default=1, verbose_name="Round Number")
    
    min_commitment = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    max_commitment = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    expected_closing_date = models.DateField(null=True, blank=True)
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='new'
    )
    workflow_status = models.CharField(
        max_length=20,
        choices=WORKFLOW_STATUS_CHOICES,
        default='draft',
        verbose_name="Workflow Status",
        help_text="Deal workflow status: Draft -> Review -> Approved"
    )
    
    approvals = models.ManyToManyField(
        User, 
        related_name='approved_deals', 
        blank=True,
        help_text="Partners/Admins who have approved this deal."
    )
    
    assigned_team_members = models.ManyToManyField(
        User,
        blank=True,
        related_name='assigned_deals',
        limit_choices_to={'role': 'team_member'},
        help_text="Team members assigned to manage this deal"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_deals'
    )
    
    def __str__(self):
        return f"{self.company_name} - Round {self.round_no}"
    
    def get_absolute_url(self):
        return reverse('deal_detail', kwargs={'pk': self.pk})
    
    
    def check_approval_status(self):
        """
        Checks if all active Partners and Admins have approved.
        If yes, sets workflow_status to 'approved'.
        """
        # Count all active Admins and Partners
        # total_approvers_needed = User.objects.filter(
        #     role__in=['admin', 'partner'], 
        #     is_active=True
        # ).count()
        
        current_approvals = self.approvals.count()
        
        if current_approvals >= 1:
            self.workflow_status = 'approved'
            # Optional: Ensure status is 'active' or 'new' once approved
            if self.status == 'new': 
                self.status = 'active'
        else:
            self.workflow_status = 'draft'
            
        self.save()
    
    class Meta:
        verbose_name = "Deal"
        verbose_name_plural = "Deals"
        ordering = ['-created_at']

class DealInternalNote(models.Model):
    """
    Internal notes for Deals with multiple entries.
    Tracks user, timestamp, and remark/status.
    """
    deal = models.ForeignKey(
        'Deal', 
        on_delete=models.CASCADE, 
        related_name='internal_notes_list'
    )
    user = models.ForeignKey(
        'User', 
        on_delete=models.SET_NULL, 
        null=True,
        help_text="User who created this note"
    )
    remark = models.TextField(help_text="Internal remark or note content")
    status = models.CharField(
        max_length=20, 
        choices=Deal.WORKFLOW_STATUS_CHOICES,
        blank=True, 
        null=True,
        help_text="Update the workflow status of the deal (optional)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Deal Internal Note"
        verbose_name_plural = "Deal Internal Notes"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Note for {self.deal.company_name} by {self.user} at {self.created_at}"

class Commitment(models.Model):
    """
    Commitment/Interest model linking Investors to Deals.
    Tracks investment interest, commitment, and payment status.
    """
    STATUS_CHOICES = [
        ('pending', 'Invitation Sent / Response Awaited'),       # Investor submitted interest / Invitation Sent / Response Awaited
        ('not_committed', 'Not Committed'),         # Not Interested
        ('committed', 'Committed'),                 # Investment Under Approval
        ('approved', 'Approved - Payment Requested'),       # Partner approved, email sent
        ('payment_uploaded', 'Payment Proof Uploaded'),     # Investor uploaded proof
        ('confirmed', 'Investment Confirmed'),                   # Money received, deal closed
        ('rejected', 'Rejected'),
    ]
    PAYMENT_TIMELINE_TYPE_CHOICES = [
        ('year', 'Year'), 
        ('weeks', 'Weeks'), 
        ('months', 'Months'), 
        ('days', 'days')
    ]   
    
    investor = models.ForeignKey(
        Investor,
        on_delete=models.CASCADE,
        related_name='commitments'
    )
    deal = models.ForeignKey(
        Deal,
        on_delete=models.CASCADE,
        related_name='commitments'
    )
    
    amount = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        help_text="Committed/Interested amount in INR",
        default=0.00
    )

    not_interested_remark = models.TextField(
        help_text="Reason for not interested",
        default="",
        blank=True,
        null=True
    )

    approved_amount = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        help_text="Approved amount in INR",
        default=0.00
    )
    
    # New Allotment Logic
    allotted_amount = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    is_allotted = models.BooleanField(default=False)
    payment_timeline = models.CharField(max_length=100, blank=True, null=True, help_text="Duration to fulfill the amount")
    payment_timeline_type = models.CharField(
        max_length=20,
        choices=PAYMENT_TIMELINE_TYPE_CHOICES,
        blank=True,
        null=True,
        default='draft',
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='interested'
    )
    payment_proof = models.FileField(
        upload_to='payment_proofs/%Y/%m/%d/',
        null=True,
        blank=True,
        help_text="Upload payment proof document"
    )
    admin_comment = models.TextField(blank=True, help_text="Internal notes")
    
    # Meeting Request
    meeting_requested = models.BooleanField(default=False, help_text="Investor requested meeting with promoters")
    questions = models.TextField(blank=True, help_text="Questions from investor")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    @property
    def proposal_display_amount(self):
        if self.status in ['pending', 'rejected', 'committed', 'payment_uploaded']:
            if self.amount != self.approved_amount or self.status == 'rejected':
                return self.amount - self.approved_amount
        return Decimal('0.00')

    @property
    def approved_display_amount(self):
        if self.status in ['approved', 'payment_uploaded']:
            return self.approved_amount
        return Decimal('0.00')

    @property
    def realized_display_amount(self):
        if self.status == 'confirmed':
            return self.approved_amount
        return Decimal('0.00')

    def __str__(self):
        return f"{self.investor.full_name} - {self.deal.company_name} - {self.status}"
    
    class Meta:
        verbose_name = "Commitment"
        verbose_name_plural = "Commitments"
        unique_together = ['investor', 'deal']
        ordering = ['-created_at']

class Document(models.Model):
    """
    Document model using generic relations to attach documents
    to Investors or Deals.
    """
    DOCUMENT_TYPE_CHOICES = [
        ('kyc', 'KYC Document'), 
        ('bank', 'Bank Statement'), 
        ('pitch_deck', 'Pitch Deck'), 
        ('financials', 'Financials'),
        
        ('write_up', 'Write Up'),
        ('one_pager', 'One Pager'),
        ('term_sheet', 'Term Sheet'),
        ('projections', 'Projections'),
    ]
    
    # Generic Foreign Key to link to Investor or Deal
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')
    
    document_type = models.CharField(
        max_length=20,
        choices=DOCUMENT_TYPE_CHOICES,
        default='other'
    )
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='documents/%Y/%m/%d/')
    description = models.TextField(blank=True)
    
    # Metadata
    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='uploaded_documents'
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.title} ({self.get_document_type_display()})"
    
    class Meta:
        verbose_name = "Document"
        verbose_name_plural = "Documents"
        ordering = ['-uploaded_at']

class SecureLink(models.Model):
    """
    SecureLink model for providing 'No Login' external access to investors.
    Generates a unique UUID token with expiry date for secure access.
    """
    investor = models.ForeignKey(
        Investor,
        on_delete=models.CASCADE,
        related_name='secure_links',
        help_text="Investor this secure link is for"
    )
    token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        help_text="Unique UUID token for secure access"
    )
    commitment = models.ForeignKey(
        'Commitment',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='secure_links',
        help_text="The specific commitment this link allows payment for."
    )
    
    # OTP Fields
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    
    expires_at = models.DateTimeField(
        help_text="Expiry date and time for this secure link"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this link is currently active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_secure_links',
        help_text="User who created this secure link"
    )
    last_accessed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time this link was accessed"
    )
    access_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this link has been accessed"
    )
    
    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.otp_created_at = timezone.now()
        self.save()
        return self.otp
    
    def verify_otp(self, input_otp):
        # OTP valid for 15 minutes
        if not self.otp or self.otp != input_otp:
            return False
        if (timezone.now() - self.otp_created_at).total_seconds() > 900:
            return False
        return True
    
    def __str__(self):
        return f"Secure Link for {self.investor.full_name} - Expires: {self.expires_at}"
    
    def is_valid(self):
        """Check if the link is still valid (active and not expired)"""
        if not self.is_active:
            return False
        return timezone.now() < self.expires_at
    
    def increment_access(self):
        """Increment access count and update last accessed timestamp"""
        self.access_count += 1
        self.last_accessed_at = timezone.now()
        self.save(update_fields=['access_count', 'last_accessed_at'])
    
    def get_absolute_url(self):
        """Generate the full secure URL for this link"""
        return reverse('investors:secure_link_access', kwargs={'token': str(self.token)})
    
    class Meta:
        verbose_name = "Secure Link"
        verbose_name_plural = "Secure Links"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['expires_at', 'is_active']),
        ]

class AuditLog(models.Model):
    """Tracks who updated what and when as per requirements"""
    ACTION_CHOICES = [('create', 'Create'), ('update', 'Update'), ('delete', 'Delete')]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')
    
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    changes = models.JSONField(help_text="JSON storage of changed fields", null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

class MyModel(models.Model):
    title = models.CharField(max_length=200, default="new title")
    content = RichTextField()

    def __str__(self):
        return self.title  