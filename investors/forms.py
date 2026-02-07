from collections.abc import Sequence
from random import choices
import attrs
from django import forms
from django.db.models import Q
from .models import Investor, User, Document, Deal, Commitment, MyModel, DealInternalNote
from django.contrib.contenttypes.models import ContentType
from ckeditor.fields import RichTextField
from ckeditor.widgets import CKEditorWidget

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        max_length=6, 
        min_length=6, 
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter 6-digit OTP'}),
        help_text="Enter the OTP sent to your registered email/mobile"
    )

class InvestorForm(forms.ModelForm):
    """ModelForm for Investor Create/Update with team member assignment logic"""
    
    preferred_industries = forms.CharField(
        widget=forms.HiddenInput(),
        required=False
    )
    
    referred_by_other = forms.CharField(        
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control mt-2',
            'placeholder': 'Enter other referrer',
            # 'style': 'display: none;' # Handled by JS
        }),
        label="Other Referrer"
    )
    
    
    class Meta:
        model = Investor        
        fields = '__all__'
        exclude = ['created_at', 'updated_at', 'created_by']
        labels = {
            'ticket_size_preference': 'Ticket size preference (Per Deal) - Declared by Investor',
            'group': 'Group (Total Deal)'    
        }
        
        widgets = {
            'full_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter full name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter email address'
            }),
            'mobile': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter mobile number'
            }),
            'address': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Enter address'
            }),
            'pan': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter PAN card number'
            }),
            'aadhaar': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter Aadhaar number'
            }),
            'dob': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date',
                'placeholder': 'dd-mm-yyyy'
            }),
            'investment_capacity': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter investment capacity in INR',
                'step': '0.01'
            }),
            'group': forms.Select(attrs={
                'class': 'form-select'
            }),
            'assigned_team_members': forms.SelectMultiple(attrs={
                'class': 'form-select'
            }),
            'family_head': forms.Select(attrs={
                'class': 'form-select'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'risk_appetite': forms.Select(attrs={'class': 'form-select'}),
            'preferred_duration': forms.Select(attrs={'class': 'form-select'}),            
            'ticket_size_preference': forms.Select(attrs={'class': 'form-select'}),
            'bank_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Bank Name'}),
            'account_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Account No'}),
            'ifsc_code': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'IFSC Code'}),
            'dp_id': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'DP ID'}),
            'client_id': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Client ID'}),
            'referred_by': forms.Select(attrs={
                'class': 'form-select',                
            }),
            'remark': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Enter internal remarks here...'
            }),
            'profession': forms.TextInput(attrs={
                'class': 'form-control'
            })             
        }
        help_texts = {
            'investment_capacity': 'Enter investment capacity in INR. Group will be auto-assigned (A if >1Cr, B if ≤1Cr).',
            'group': 'Group is automatically assigned based on investment capacity, but can be manually overridden.',
            'family_head': 'Select a primary investor (family head) to link this investor as a family member.',
        }
    
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # Store user for later use in save()
        self._user = user
        
        # Pre-select values from JSONField - convert to JSON string for hidden input
        import json
        if self.instance and self.instance.pk:
            # Editing existing investor
            industries_data = self.instance.preferred_industries
            if industries_data:
                # Has data - convert to JSON string
                # WE MUST UPDATE self.initial DIRECTLY because ModelForm populates it 
                # and it takes precedence over field level initial
                json_val = json.dumps(industries_data.value if hasattr(industries_data, 'value') else industries_data)
                self.initial['preferred_industries'] = json_val
                self.fields['preferred_industries'].initial = json_val
            else:
                # Empty list or None
                self.initial['preferred_industries'] = '[]'
                self.fields['preferred_industries'].initial = '[]'
        else:
            # New investor - default to empty
            self.initial['preferred_industries'] = '[]'
            self.fields['preferred_industries'].initial = '[]'

        # Filter assigned_team_members queryset to only show team members
        self.fields['assigned_team_members'].queryset = User.objects.filter(role='team_member')
        
        # Role-based logic for assigned_team_members field
        if user:
            if user.is_team_member:
                # Team members: Disable the field (it will be auto-assigned in save())
                self.fields['assigned_team_members'].disabled = True
            else:
                # Partners/Admins: Can select multiple team members
                pass
        
        # Filter family_head queryset - exclude self to prevent circular references
        # And exclude investors who are already assigned to a family head
        qs = Investor.objects.filter(family_head__isnull=True)
        
        if user and user.is_team_member:
            # Team members should only see their own investors as potential family heads
            qs = qs.filter(Q(created_by=user) | Q(assigned_team_members=user)).distinct()
            
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        self.fields['family_head'].queryset = qs
        self.fields['family_head'].empty_label = '-- Principal Investor / Family Head --'  

        # Dynamic choices for referred_by
        users = list(User.objects.all().values_list('username', flat=True))
        if user and user.is_team_member:
            # Team members should only see their own investors as potential family heads
            investors = list(Investor.objects.filter(Q(created_by=user) | Q(assigned_team_members=user)).distinct().values_list('full_name', flat=True))
        else:
            investors = list(Investor.objects.all().values_list('full_name', flat=True))
        
        referrer_choices = [
            ('', 'Select Referrer'),
            ('Users', [(u, u) for u in users]),
            ('Investors', [(i, i) for i in investors]),
            ('Other', [('other', 'Other')])
        ]
        self.fields['referred_by'].widget.choices = referrer_choices
        
        # Initial Value Logic for Edit Mode
        if self.instance and self.instance.pk and self.instance.referred_by:
            current_ref = self.instance.referred_by
            if current_ref in users or current_ref in investors:
                self.initial['referred_by'] = current_ref
            else:
                self.initial['referred_by'] = 'other'
                self.initial['referred_by_other'] = current_ref

    def clean(self):
        cleaned_data = super().clean()
        referred_by = cleaned_data.get('referred_by')
        referred_by_other = cleaned_data.get('referred_by_other')

        if referred_by == 'other':
            if not referred_by_other:
                self.add_error('referred_by_other', 'Please specify the referrer name.')
            else:
                cleaned_data['referred_by'] = referred_by_other
        
        return cleaned_data  
    
    def clean_preferred_industries(self):
        """Parse JSON string from hidden input and validate industry choices"""
        import json
        data = self.cleaned_data.get("preferred_industries", "")
        
        # Handle empty data
        if not data or data == "[]":
            return []
        
        try:
            industries = json.loads(data)
            
            # Validate all industries are valid choices
            valid_choices = [choice[0] for choice in Investor.INDUSTRY_CHOICES]
            for industry in industries:
                if industry not in valid_choices:
                    raise forms.ValidationError(f"Invalid industry: {industry}")
            
            return industries
        except json.JSONDecodeError:
            raise forms.ValidationError("Invalid data format for preferred industries")
    
    def clean_assigned_team_members(self):
        """Ensure only team members can be assigned"""
        assigned = self.cleaned_data.get('assigned_team_members')
        if assigned:
            for user in assigned:
                if user.role != 'team_member':
                    raise forms.ValidationError('Only team members can be assigned to investors.')
        return assigned
    
    def clean_family_head(self):
        """Prevent self-referential family head assignment"""
        family_head = self.cleaned_data.get('family_head')
        if family_head and self.instance.pk and family_head.pk == self.instance.pk:
            raise forms.ValidationError('An investor cannot be their own family head.')
        return family_head
    
    def save(self, commit=True):
        """Save form and auto-assign team members"""
        # Get user from form initialization
        user = getattr(self, '_user', None)
        
        # Set created_by ONLY for new instances
        if not self.instance.pk and user:
            self.instance.created_by = user
            
        instance = super().save(commit=commit)
        
        # If team member is creating or updating, auto-assign them
        if user and user.is_team_member:
            # Add current user to assigned_team_members
            instance.assigned_team_members.add(user)
        return instance

class InvestorBulkUploadForm(forms.Form):
    file = forms.FileField(
        label="Upload Excel/CSV File",
        help_text="Upload a .xlsx or .csv file. Required columns: Full Name, Email, Mobile, PAN, Aadhaar, DOB (YYYY-MM-DD), Address."
    )
class ExternalInvestorForm(forms.ModelForm):
    """Form for external investors to update their information via secure link"""
    
    # KYC Document uploads
    pan_document = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
        }),
        help_text='Upload PAN card document (PDF, JPG, PNG)'
    )
    aadhaar_document = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
        }),
        help_text='Upload Aadhaar card document (PDF, JPG, PNG)'
    )
    bank_statement = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
        }),
        help_text='Upload bank statement (PDF, JPG, PNG)'
    )
    
    class Meta:
        model = Investor
        fields = [
            'full_name', 'email', 'mobile', 'address', 'dob', 'profession',
            'pan', 'aadhaar', 
            'bank_name', 'account_number', 'ifsc_code',
            'dp_id', 'client_id', 'preferred_industries',
        ]
        widgets = {
            'full_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter full name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter email address'
            }),
            'mobile': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter mobile number'
            }),
            'address': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter complete address'
            }),
            'pan': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter PAN card number',
                'maxlength': '10'
            }),
            'aadhaar': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter Aadhaar number',
                'maxlength': '12'
            }),
            'dob': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date',
                'placeholder': 'dd-mm-yyyy'
            }),
            'profession': forms.TextInput(attrs={
                'class': 'form-control'
            }),            
        }
        
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make fields required
        self.fields['full_name'].required = True
        self.fields['email'].required = True
        self.fields['mobile'].required = True
        self.fields['address'].required = True
        self.fields['pan'].required = True
        self.fields['aadhaar'].required = True
        self.fields['dob'].required = True
    
    def clean_pan(self):
        """Validate PAN format"""
        pan = self.cleaned_data.get('pan', '').strip().upper()
        if len(pan) != 10:
            raise forms.ValidationError('PAN must be 10 characters long.')
        return pan
    
    def clean_aadhaar(self):
        """Validate Aadhaar format"""
        aadhaar = self.cleaned_data.get('aadhaar', '').strip()
        if len(aadhaar) != 12 or not aadhaar.isdigit():
            raise forms.ValidationError('Aadhaar must be 12 digits.')
        return aadhaar
    
    def clean_mobile(self):
        """Validate mobile number"""
        mobile = self.cleaned_data.get('mobile', '').strip()
        if not mobile:
            raise forms.ValidationError('Mobile number is required.')
        return mobile
class DealForm(forms.ModelForm):
    """Form for Deal Create/Update with document uploads"""
    
    pitch_deck = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.pptx,.ppt'
        }),
        help_text='Upload Pitch Deck document (PDF, PPTX, PPT)'
    )
    financials = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.xlsx,.xls'
        }),
        help_text='Upload Financials document (PDF, XLSX, XLS)'
    )
    write_up = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.pdf,.doc,.docx'}),
        help_text='Upload Write Up / Teaser (PDF, Word)'
    )
    one_pager = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.pdf,.jpg,.png'}),
        help_text='Upload One Pager (PDF, Image)'
    )
    term_sheet = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.pdf,.doc,.docx'}),
        help_text='Upload Term Sheet (PDF, Word)'
    )
    projections = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.pdf,.xlsx,.xls'}),
        help_text='Upload Projections (PDF, Excel)'
    )
    
    class Meta:
        model = Deal
        fields = '__all__'
        exclude = ['created_at', 'updated_at', 'created_by']
        
        widgets = {
            'company_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter company name'
            }),
            'category': forms.Select(attrs={
                'class': 'form-select'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter deal description'
            }),
            'video_url': forms.URLInput(attrs={
                'class': 'form-control',
                'placeholder': 'https://youtube.com/...'
            }),
            'deal_size': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter total deal size in INR',
                'step': '0.01'
            }),
            'ticket_size': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter minimum ticket size in INR',
                'step': '0.01'
            }),
            'round_no': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter round number'
            }),
            'expected_closing_date': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'status': forms.Select(attrs={
                'class': 'form-select'
            }),
            'workflow_status': forms.Select(attrs={
                'class': 'form-select'
            }),
            'assigned_team_members': forms.SelectMultiple(attrs={
                'class': 'form-select select2',
                'multiple': 'multiple'
            })
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        if user:
            if user.role == 'team_member':
                self.fields['workflow_status'].disabled = True
            elif user.role in ['partner', 'admin']:
                self.fields['workflow_status'].choices = [
                    ('review', 'Review'),
                    ('approved', 'Approved'),
                ]

        # Filter assigned_team_members to only show team members
        if 'assigned_team_members' in self.fields:
            self.fields['assigned_team_members'].queryset = User.objects.filter(role='team_member')

            # Hide if current user is team_member (as requested "not visible to user" meaning team member)
            if user and user.role == 'team_member':
                self.fields['assigned_team_members'].widget = forms.HiddenInput()
                self.fields['assigned_team_members'].required = False


class DealInterestForm(forms.Form):
    """Form for investors to express interest in a deal"""
    
    ACTION_CHOICES = [
        ('interested', 'Interested'),
        ('not_interested', 'Not Interested'),
        ('commit', 'Commit Amount'),
    ]
    
    action = forms.ChoiceField(choices=ACTION_CHOICES, widget=forms.RadioSelect)
    committed_amount = forms.DecimalField(required=False, widget=forms.NumberInput(attrs={'placeholder': 'Amount'}))
    approved_amount = forms.DecimalField(required=False, widget=forms.NumberInput(attrs={'placeholder': 'Amount'}))
    payment_timeline = forms.DecimalField(required=False, widget=forms.NumberInput(attrs={'placeholder': 'Amount'}))
    payment_timeline_type = forms.ChoiceField(choices=Commitment.PAYMENT_TIMELINE_TYPE_CHOICES, required=False)
    not_interested_remark = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Any remarks?'}), required=False)
    request_meeting = forms.BooleanField(
        required=False, 
        label="Request Meeting with Promoters",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    questions = forms.CharField(
        required=False, 
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'Any questions?'})
    )
    
    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')
        committed_amount = cleaned_data.get('committed_amount')
        not_interested_remark = cleaned_data.get('not_interested_remark')
        
        if action == 'commit' and not committed_amount:
            raise forms.ValidationError({'committed_amount': 'Please enter the commitment amount.'})
        if action != 'commit' and committed_amount:
            cleaned_data['committed_amount'] = None        

class HierarchicalUserCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password', 'role']

    def __init__(self, *args, **kwargs):
        self.creator = kwargs.pop('creator', None)
        super().__init__(*args, **kwargs)
        # Filter roles based on who is creating the user
        if self.creator.is_admin:
            self.fields['role'].choices = [('partner', 'Partner'), ('team_member', 'Team Member')]
        elif self.creator.is_partner:
            self.fields['role'].choices = [('team_member', 'Team Member')]
        else:
            self.fields['role'].choices = []
            
class DealInternalNoteForm(forms.ModelForm):
    class Meta:
        model = DealInternalNote
        fields = ['remark']
        widgets = {
            'remark': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Add internal note or remark...'
            }),
            'status': forms.Select(attrs={
                'class': 'form-select'
            }),
        }

class DealSendForm(forms.Form):
    """Form to select multiple investors to send deal to"""
    
    existing_template = forms.ModelChoiceField(
        queryset=MyModel.objects.all(),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Existing Template",
    )
    investors = forms.ModelMultipleChoiceField(
        queryset=Investor.objects.all(),
        widget=forms.CheckboxSelectMultiple
    )    
    expiry_days = forms.IntegerField(
        min_value=1, 
        max_value=365, 
        initial=7,
        label="Link Expiry (Days)",
        help_text="How many days should this link remain valid?",
        widget=forms.NumberInput(attrs={'class': 'form-control', 'style': 'max-width: 150px;'})
    )   
    subject = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Email Subject'})
    )
    content = forms.CharField(
        required=False,
        widget=CKEditorWidget(attrs={'style': 'width: 100% !important;'}),
        label="Email Content"
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user and user.is_team_member:
            self.fields['investors'].queryset = Investor.objects.filter(Q(assigned_team_members=user) | Q(is_active=True))
        else:
            self.fields['investors'].queryset = Investor.objects.filter(is_active=True)       
            
class CommitmentForm(forms.ModelForm):
    class Meta:
        model = Commitment
        fields = ['investor', 'deal', 'amount', 'approved_amount', 'status', 'payment_proof']
        widgets = {
            'investor': forms.Select(attrs={'class': 'form-select'}),
            'deal': forms.Select(attrs={'class': 'form-select'}),
            'amount': forms.NumberInput(attrs={'class': 'form-control'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'payment_proof': forms.FileInput(attrs={'class': 'form-control'}),
            'approved_amount': forms.NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        self.submit_button = "Save"
        if user and not user.is_partner:
            self.fields['investor'].queryset = Investor.objects.filter(Q(assigned_team_members=user) | Q(created_by=user), is_active=True)
            self.fields['deal'].queryset = Deal.objects.filter(Q(created_by=user) | Q(assigned_team_members=user)).distinct().filter(workflow_status="approved")
            self.fields['payment_proof'].required = False
        else:
            self.fields['investor'].queryset = Investor.objects.filter(is_active=True)
            self.fields['deal'].queryset = Deal.objects.filter(workflow_status="approved")   

        if self.instance and self.instance.pk:
            self.fields['investor'].disabled = True
            self.fields['deal'].disabled = True
            self.fields['amount'].disabled = True 
            self.fields['approved_amount'].disabled = True   
            self.fields['status'].disabled = True
            self.fields['payment_proof'].disabled = True
            
            if(self.instance.status == "pending"):
                pass

            elif(self.instance.status == "not_committed"):
                pass

            elif(self.instance.status == "committed"):
                self.fields['approved_amount'].disabled = False
                self.submit_button = "Approve" 

            elif(self.instance.status == "approved"):
                self.fields['payment_proof'].disabled = False
                self.fields['payment_proof'].required = True
                self.submit_button = "Verify Proof and Confirm Deal" 

            elif(self.instance.status == "payment_uploaded"):
                self.submit_button = "Approved Deal" 

            elif(self.instance.status == "confirmed"):
                self.submit_button = "Confirmed Deal"

            elif(self.instance.status == "rejected"):
                self.submit_button = "Rejected Deal"        

        else:
            self.fields['status'].disabled = True
            self.fields['payment_proof'].required = False
            self.fields['amount'].initial = ""
            self.fields['approved_amount'].initial = ""
            

class MyModelForm(forms.ModelForm):
    existing_template = forms.ModelChoiceField(
        queryset=MyModel.objects.all(),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select', 'onchange': 'this.form.submit()'}),
        label="Existing Template",
    )
    class Meta:
        model = MyModel
        fields = ['title', 'content', 'existing_template']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'style': 'max-width: 150px;'}),            
            'content': forms.CharField(widget=CKEditorWidget(attrs={'class': 'form-full-width'})),            
        } 
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        templates = list(MyModel.objects.all().values_list('title', flat=True))
        referrer_choices = [
            ('', 'Select Template'),       
            ('Templates', [(i, i) for i in templates]),
            ('Other', [('other', 'Other')])
        ]
        self.fields['existing_template'].choices = referrer_choices