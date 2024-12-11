from django.urls import path
from .views import LoginView,RegistrationView,LogoutView,ChatView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegistrationView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('chatbot/', ChatView.as_view(), name='chat'),
]
