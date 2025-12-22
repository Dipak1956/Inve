from django import forms
from .models import Investor, User, Document, Deal
from django.contrib.contenttypes.models import ContentType


class InvestorForm(forms.ModelForm):
    """ModelForm for Investor Create/Update with team member assignment logic"""
    
    class Meta:
        model = Investor
        fields = [
            'full_name', 'email', 'mobile', 'address', 'pan', 'aadhaar', 'dob',
            'investment_capacity', 'group', 'assigned_team_member', 'family_head'
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
                'type': 'date'
            }),
            'investment_capacity': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter investment capacity in INR',
                'step': '0.01'
            }),
            'group': forms.Select(attrs={
                'class': 'form-select'
            }),
            'assigned_team_member': forms.Select(attrs={
                'class': 'form-select'
            }),
            'family_head': forms.Select(attrs={
                'class': 'form-select'
            }),
        }
        help_texts = {
            'investment_capacity': 'Enter investment capacity in INR. Group will be auto-assigned (A if >1Cr, B if ≤1Cr).',
            'group': 'Group is automatically assigned based on investment capacity, but can be manually overridden.',
            'family_head': 'Select a primary investor (family head) to link this investor as a family member.',
        }
    
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # Filter assigned_team_member queryset to only show team members
        self.fields['assigned_team_member'].queryset = User.objects.filter(
            role='team_member'
        )
        self.fields['assigned_team_member'].empty_label = '-- Not Assigned --'
        
        # Filter family_head queryset - exclude self to prevent circular references
        if self.instance and self.instance.pk:
            self.fields['family_head'].queryset = Investor.objects.exclude(
                pk=self.instance.pk
            )
        else:
            self.fields['family_head'].queryset = Investor.objects.all()
        self.fields['family_head'].empty_label = '-- None (Primary Investor) --'
        
        # If user is a team member (not admin/partner), pre-fill assigned_team_member
        if user and user.is_team_member and not self.instance.pk:
            # For new investors, auto-assign to the team member creating them
            self.fields['assigned_team_member'].initial = user
    
    def clean_assigned_team_member(self):
        """Ensure only team members can be assigned"""
        assigned = self.cleaned_data.get('assigned_team_member')
        if assigned and assigned.role != 'team_member':
            raise forms.ValidationError('Only team members can be assigned to investors.')
        return assigned
    
    def clean_family_head(self):
        """Prevent self-referential family head assignment"""
        family_head = self.cleaned_data.get('family_head')
        if family_head and self.instance.pk and family_head.pk == self.instance.pk:
            raise forms.ValidationError('An investor cannot be their own family head.')
        return family_head


class ExternalInvestorForm(forms.ModelForm):
    """Form for external investors to update their information via secure link"""
    
    # KYC Document uploads
    pan_document = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.jpg,.jpeg,.png'
        }),
        help_text='Upload PAN card document (PDF, JPG, PNG)'
    )
    aadhaar_document = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.jpg,.jpeg,.png'
        }),
        help_text='Upload Aadhaar card document (PDF, JPG, PNG)'
    )
    bank_statement = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.jpg,.jpeg,.png'
        }),
        help_text='Upload bank statement (PDF, JPG, PNG)'
    )
    
    class Meta:
        model = Investor
        fields = [
            'full_name', 'email', 'mobile', 'address', 'pan', 'aadhaar', 'dob'
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
                'type': 'date'
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
    
    class Meta:
        model = Deal
        fields = [
            'company_name', 'description', 'deal_size', 'ticket_size',
            'round_no', 'status', 'workflow_status'
        ]
        widgets = {
            'company_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter company name'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Enter deal description'
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
            'status': forms.Select(attrs={
                'class': 'form-select'
            }),
            'workflow_status': forms.Select(attrs={
                'class': 'form-select'
            }),
        }


class DealInterestForm(forms.Form):
    """Form for investors to express interest in a deal"""
    
    ACTION_CHOICES = [
        ('interested', 'Interested'),
        ('not_interested', 'Not Interested'),
        ('commit', 'Commit Amount'),
    ]
    
    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        })
    )
    committed_amount = forms.DecimalField(
        max_digits=15,
        decimal_places=2,
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter commitment amount in INR',
            'step': '0.01'
        }),
        help_text='Required if committing to invest'
    )
    
    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')
        committed_amount = cleaned_data.get('committed_amount')
        
        if action == 'commit' and not committed_amount:
            raise forms.ValidationError({
                'committed_amount': 'Please enter the commitment amount.'
            })
        
        if action != 'commit' and committed_amount:
            cleaned_data['committed_amount'] = None
        
        return cleaned_data
