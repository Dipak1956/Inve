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
    
    # Commitment URLs
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
]

