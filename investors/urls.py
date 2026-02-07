from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

app_name = 'investors'

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', LogoutView.as_view(next_page='investors:login'), name='logout'),
        
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    
    # User Management
    path('users/create/', views.UserCreateView.as_view(), name='user_create'),
    path('users/', views.UserManagementView.as_view(), name='user_list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    path('users/<int:pk>/edit/', views.UserUpdateView.as_view(), name='user_edit'),
    path('users/<int:pk>/user_password_reset/', views.user_password_reset, name='user_password_reset'),
    
    # Investor URLs
    path('investors/', views.InvestorListView.as_view(), name='investor_list'),
    path('investors/<int:pk>/', views.InvestorDetailView.as_view(), name='investor_detail'),
    path('investors/create/', views.InvestorCreateView.as_view(), name='investor_create'),
    path('investors/<int:pk>/update/', views.InvestorUpdateView.as_view(), name='investor_update'),
    path('investors/<int:pk>/delete/', views.InvestorDeleteView.as_view(), name='investor_delete'),
    
    # Deal URLs
    path('deals/', views.DealListView.as_view(), name='deal_list'),
    path('deals/<int:pk>/', views.DealDetailView.as_view(), name='deal_detail'),
    path('deals/create/', views.DealCreateView.as_view(), name='deal_create'),
    path('deals/<int:pk>/update/', views.DealUpdateView.as_view(), name='deal_update'),
    path('deals/<int:pk>/delete/', views.DealDeleteView.as_view(), name='deal_delete'),
    
    # Commitment URLss
    path('commitments/', views.CommitmentListView.as_view(), name='commitment_list'),
    path('commitments/create/', views.CommitmentCreateView.as_view(), name='commitment_create'),
    path('commitments/<int:pk>/update/', views.CommitmentUpdateView.as_view(), name='commitment_update'),
    path('commitments/<int:pk>/delete/', views.CommitmentDeleteView.as_view(), name='commitment_delete'),
    
    # External Investor Form (Public - No login required)
    path('external/<uuid:token>/', views.external_investor_form, name='external_investor_form'),
    path('secure-link/<uuid:token>/', views.external_investor_form, name='secure_link_access'),
    
    # Deal Interest Collection (Public - No login required)
    path('deal/<uuid:token>/<int:deal_id>/', views.deal_interest_view, name='deal_interest'),
    
    # Deal Dashboard (Internal)
    path('deals/<int:deal_id>/dashboard/', views.deal_dashboard, name='deal_dashboard'),
    
    # Send Deal Invitation
    path('deals/<int:pk>/send/', views.send_deal_view, name='deal_send'),
    
    # Internal Workflow Actions
    path('commitment/<int:pk>/approve/', views.approve_commitment, name='commitment_approve'),
    path('commitment/<int:pk>/confirm/', views.confirm_commitment, name='commitment_confirm'),
    path('investors/<int:pk>/active/', views.active_invester, name='active_invester'),
    path('deals/<int:pk>/approve/', views.approve_deal, name='deal_approve'),

    # External Investor Actions
    path('commitment/<int:pk>/upload-payment/', views.upload_payment_view, name='upload_payment'),
    path('payment-access/<uuid:token>/', views.payment_link_access, name='payment_link_access'),
    path('upload-payment/<uuid:token>/', views.upload_payment_view, name='upload_payment'),
    
    # These were missing and causing the NoReverseMatch error
    path('auth/otp/<uuid:token>/', views.external_access_otp, name='external_access_otp'),
    path('auth/verify-otp/', views.verify_otp_view, name='verify_otp'),

    path('investors/bulk-upload/', views.InvestorBulkUploadView.as_view(), name='investor_bulk_upload'),
    path('investors/bulk-upload/demo/', views.download_demo_file, name='download_demo_file'), # <--- ADD THIS
    path('deals/<int:pk>/approve/', views.approve_deal, name='deal_approve'),
    
    path('login/registerinvester', views.InvestorSelfSignUp, name='investor_create_self'),
    
    path('emails_templates/', views.email_editor, name='emails_templates'),
]

