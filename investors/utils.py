# investors/utils.py
from django.core.mail import send_mail
from django.core.mail import get_connection, EmailMultiAlternatives
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from requests import request
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .models import SecureLink, MyModel

from django.template import Template, Context
from django.conf import settings
import os
from datetime import timedelta
from .models import MyModel
from django.core.mail import send_mail
from django.conf import settings
import phonenumbers
from phonenumbers import carrier
from phonenumbers import geocoder
from phonenumbers import timezone as ph_timezone


def get_safe_full_name(user):
    """Helper to safely get full name even for AnonymousUser or None"""
    if user and hasattr(user, 'is_authenticated') and user.is_authenticated:
        return user.get_full_name() or user.username
    return "System"

def get_safe_email(user):
    """Helper to safely get email even for AnonymousUser or None"""
    if user and hasattr(user, 'is_authenticated') and user.is_authenticated:
        return user.email
    return ""

def generate_deal_email_content(request, investor, deal, secure_link, custom_subject=None, custom_content=None):
    """
    Helper to generate the Subject and Message Body for Preview and Sending.
    Allows overriding the template and subject via arguments.
    """
    link_url = request.build_absolute_uri(
        reverse('investors:deal_interest', kwargs={
            'token': secure_link.token,
            'deal_id': deal.id
        })
    )        
    subject = custom_subject or f"Invitation: Investment Opportunity in {deal.company_name}"
    
    # If custom_content is provided, use it. Otherwise, fetch default from MyModel.
    email_template_content = custom_content
    if not email_template_content:
        template_obj = MyModel.objects.filter(title='Send Deal').first()
        email_template_content = template_obj.content if template_obj else ""

    context = {
        'investor': investor,
        'deal': deal,
        'link_url': link_url,
        'secure_link': secure_link.expires_at.strftime("%d %b %Y"),
        'request': request,
        'user': get_safe_full_name(request.user),
        'user_email': get_safe_email(request.user),
    }
    
    # Render placeholders in the content
    message_body = render_text_format(email_template_content, context)
    return subject, message_body

def send_otp_email(sender_user, investor, otp, request=None):
    """
    Sends the OTP to the investor using the credentials of the User who created the link.
    """
    # 1. Validation: Ensure the sender (Link Creator) has credentials
    if not sender_user or not sender_user.email or not sender_user.smtp_password:
        print(f"ERROR: User {sender_user} has no SMTP credentials. Cannot send OTP.")
        return False

    subject = "Your Security Code (OTP) - Beeline InvestHub"    
    email_template = MyModel.objects.get(title='Send Email Otp').content
    context = {
        'investor': investor,
        'otp': otp,
        'sender_user': get_safe_full_name(sender_user),
        'request': request,
        'user': get_safe_full_name(sender_user),
        'user_email': get_safe_email(sender_user),
    }
    message_body = render_text_format(email_template, context)
    try:
        # 2. Configure connection using Sender's Credentials
        connection = get_connection(
            backend='django.core.mail.backends.smtp.EmailBackend',
            host='smtp.gmail.com',
            port=587,
            username=sender_user.email,
            password=sender_user.smtp_password,
            use_tls=True,
            timeout=10
        )
        
        # 3. Send Email
        email = EmailMultiAlternatives(
            subject=subject,
            body=message_body,
            from_email=sender_user.email,
            to=[investor.email],
            connection=connection
        )
        
        email.content_subtype = "html"
        email.send()
        print(f"--- OTP SENT TO {investor.email} VIA {sender_user.email} ---")
        return True
        
    except Exception as e:
        print(f"SMTP Error sending OTP: {e}")
        return False

def send_mail_via_user_credentials(request, investor, subject, message_body, sender_user=None):
    """
    Sends email using the provided sender_user's or current User's SMTP settings.
    """
    if sender_user is None:
        sender_user = request.user
    
    # Check if sender_user is authenticated and has credentials
    if not hasattr(sender_user, 'is_authenticated') or not sender_user.is_authenticated:
        print(f"ERROR: No authenticated sender user available for SMTP.")
        return False, "User not authenticated. Cannot send email."

    if not sender_user.smtp_password:
        print(f"ERROR: User {sender_user.username} has no SMTP credentials.")
        return False, "SMTP Credentials (App Password) missing in your profile."

    # 2. Configure the connection dynamically
    try:
        connection = get_connection(
            backend='django.core.mail.backends.smtp.EmailBackend',
            host='smtp.gmail.com',
            port=587,
            username=sender_user.smtp_email or sender_user.email,
            password=sender_user.smtp_password,
            use_tls=True,
            timeout=10
        )
        
        # 3. Create the email
        text_content = strip_tags(message_body) # Plain text fallback
        
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content, 
            from_email=sender_user.smtp_email or sender_user.email,
            to=[investor.email],
            connection=connection           
        )     
        email.attach_alternative(message_body, "text/html")
        
        # 4. Send
        email.send()
        return True, "Sent successfully"
        
    except Exception as e:
        print(f"SMTP Error: {e}")
        return False, str(e)
    
def send_deal_invitation(request, investor, deal, secure_link):
    """
    Sends the initial deal email with the Secure Link.
    """
    subject = f"Investment Opportunity: {deal.company_name}"
    
    # Generate the absolute URL for the secure link
    link_url = request.build_absolute_uri(
        reverse('investors:deal_interest', kwargs={
            'token': secure_link.token,
            'deal_id': deal.id
        })
    )
    
    subject = f"Invitation: Investment Opportunity in {deal.company_name}"
    email_template = MyModel.objects.get(title='Send Deal Invitation').content
    context = {
        'investor': investor,
        'deal': deal,
        'link_url': link_url,
        'secure_link': secure_link.expires_at.strftime("%d %b %Y"),
        'request': request
    }
    message_body = render_text_format(email_template, context)
    
    
    # In production, use send_mail()
    # For now, we print to console to verify it works without SMTP setup
    print(f"--- EMAIL SENT TO {investor.email} ---")
    print(message_body)
    print("--------------------------------------")

def send_payment_request(request, commitment):
    """
    Creates a Secure Link for payment and sends it via email.
    """
    investor = commitment.investor
    deal = commitment.deal
    
    # 1. Create a Secure Link linked to this commitment
    # Expires in 7 days (or your preference)
    expiry_date = timezone.now() + timedelta(days=7)
    secure_link = SecureLink.objects.create(
        investor=investor,
        commitment=commitment,
        created_by=request.user,
        expires_at=expiry_date,
        is_active=True
    )
    
    # 2. Generate the URL to the Access View (Step 1 of flow)
    upload_url = request.build_absolute_uri(
        reverse('investors:payment_link_access', kwargs={'token': secure_link.token})
    )
    
    subject = f"Action Required: Payment Details for {deal.company_name}"
    email_template = MyModel.objects.get(title='Send Payment Request').content
    context = {
        'investor': investor,
        'commitment': commitment,
        'upload_url': upload_url, 
        'user': get_safe_full_name(request.user),
        'user_email': get_safe_email(request.user),
        'deal': deal,
        'request': request,
    }
    message = render_text_format(email_template, context)
    success, msg = send_mail_via_user_credentials(request, investor, subject, message)
    
    if success:
        print(f"--- PAYMENT EMAIL SENT TO {investor.email} ---")
        return True, "Email sent successfully"
    else:
        print(f"--- FAILED TO SEND EMAIL: {msg} ---")
        return False, msg
    
def send_confirmation_email(request, commitment):
    """
    Sends the "Payment Received & Confirmed" email to the investor.
    """
    investor = commitment.investor
    deal = commitment.deal
    
    subject = f"Success: Investment Confirmed in {deal.company_name}"
    
    email_template = MyModel.objects.get(title='Send Confirmation Email').content
    context = {
        'investor': investor,
        'commitment': commitment,
        'user': get_safe_full_name(request.user),
        'user_email': get_safe_email(request.user),
        'deal': deal,
        'request': request
    }
    message = render_text_format(email_template, context)
    return send_mail_via_user_credentials(request, investor, subject, message)

def send_thankyou_email_not_committed(request, commitment, sender_user=None):
    
    investor = commitment.investor
    deal = commitment.deal
    
    subject = f"Thank you for your reply in {deal.company_name}"
    
    email_template = MyModel.objects.get(title='Not Interested Thankyou').content
    context = {
        'investor': investor,
        'commitment': commitment,
        'user': get_safe_full_name(sender_user or request.user),
        'user_email': get_safe_email(sender_user or request.user),
        'deal': deal,
        'request': request
    }
    message = render_text_format(email_template, context)
    return send_mail_via_user_credentials(request, investor, subject, message, sender_user=sender_user)    

def send_rejected_email(request, commitment):
    """
    Sends the "Commitment Rejected" email to the investor.
    """
    investor = commitment.investor
    deal = commitment.deal
    
    subject = f"Commitment Rejected for {deal.company_name}"
    
    email_template = MyModel.objects.get(title='Send Rejected Email').content
    context = {
        'investor': investor,
        'user': get_safe_full_name(request.user),
        'user_email': get_safe_email(request.user),
        'deal': deal,
        'request': request
    }
    message = render_text_format(email_template, context)
    return send_mail_via_user_credentials(request, investor, subject, message)    

def send_deal_closure_email(request, commitment, deal):  

    """
    Sends the Deal Closure notification to all investors who showed interest.
    """
    investor = commitment.investor
       
    subject = f"Update: Deal Closure for "

    email_template = MyModel.objects.get(title='Send Deal Closure Emai').content
    context = {
        'investor': investor,
        'user': get_safe_full_name(request.user),
        'user_email': get_safe_email(request.user),
        'deal': deal,
        'request': request,
    }
    message = render_text_format(email_template, context) 

    # Send email to each interested investor
    return send_mail_via_user_credentials(request, investor, subject, message)

def render_text(raw_text: str, data: dict) -> str:
    """
    Converts raw stored text into preview/sent version
    """
    template = Template(raw_text)
    context = Context(data)
    return template.render(context) 

def render_text_format(raw_text: str, data: dict) -> str:
    return raw_text.format(**data)    

def send_deal_invitation_via_whatspp(request, investor, subject, body):  
    # 2. Configure connection using Sender's Credentials
    connection = get_connection(
        backend='django.core.mail.backends.smtp.EmailBackend',
        host='smtp.gmail.com',
        port=587,
        username=request.user.email,
        password=request.user.smtp_password,
        use_tls=True,
        timeout=10)
    
    number = phonenumbers.parse("+919662773774")
    service_provider = carrier.name_for_number(number, "en")
    print(f"Service Provider: {service_provider}")
    location = geocoder.description_for_number(number, "en")
    print(f"Location: {location}")
    time_zones = ph_timezone.time_zones_for_number(number)
    print(f"Timezone(s): {time_zones}")