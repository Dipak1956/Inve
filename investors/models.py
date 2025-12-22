from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
from django.urls import reverse
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from decimal import Decimal
import uuid


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
        ('A', 'Group A (>1Cr)'),
        ('B', 'Group B (≤1Cr)'),
    ]
    
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
    address = models.TextField()
    
    # KYC Information
    pan = models.CharField(max_length=10, unique=True, help_text="PAN Card Number")
    aadhaar = models.CharField(max_length=12, unique=True, help_text="Aadhaar Number (will be masked in display)")
    dob = models.DateField(verbose_name="Date of Birth")
    
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
        max_length=1,
        choices=GROUP_CHOICES,
        default='B',
        help_text="Group A for investments >1Cr, Group B for ≤1Cr (auto-assigned based on investment_capacity)"
    )
    
    # Relationships
    assigned_team_member = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_investors',
        limit_choices_to={'role': 'team_member'},
        help_text="Team member assigned to manage this investor"
    )
    family_head = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='family_members',
        help_text="Family head for family grouping"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        """
        Automatically assign Group A or Group B based on investment_capacity.
        Group A: investment_capacity > 1,00,00,000 (1 Crore)
        Group B: investment_capacity ≤ 1,00,00,000 (1 Crore)
        """
        if self.investment_capacity is not None:
            # 1 Crore = 1,00,00,000 = 10000000
            one_crore = Decimal('10000000')
            if self.investment_capacity > one_crore:
                self.group = 'A'
            else:
                self.group = 'B'
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.full_name} ({self.email})"
    
    def get_masked_aadhaar(self):
        """Returns masked Aadhaar number for display (first 4 and last 4 visible)"""
        if len(self.aadhaar) >= 8:
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
        ('closing', 'Closing'),
        ('closed', 'Closed'),
    ]
    
    WORKFLOW_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('review', 'Review'),
        ('approved', 'Approved'),
    ]
    
    # Basic Information
    company_name = models.CharField(max_length=255)
    description = models.TextField()
    
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
    
    class Meta:
        verbose_name = "Deal"
        verbose_name_plural = "Deals"
        ordering = ['-created_at']


class Commitment(models.Model):
    """
    Commitment/Interest model linking Investors to Deals.
    Tracks investment interest, commitment, and payment status.
    """
    STATUS_CHOICES = [
        ('interested', 'Interested'),
        ('committed', 'Committed'),
        ('paid', 'Paid'),
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
        help_text="Committed/Interested amount in INR"
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
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
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
        ('deal_doc', 'Deal Document'),
        ('other', 'Other'),
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
