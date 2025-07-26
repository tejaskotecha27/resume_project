from django.urls import path

from . import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('analyze/', views.analyze_resume_view, name='analyze'),
    path('resume-edit/', views.resume_edit_view, name='resume_edit'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
]