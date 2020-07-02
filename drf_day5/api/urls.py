from django.urls import path

from api import views

urlpatterns = [
    path("test/", views.TestAPIView.as_view()),
    path("is_auth/", views.TestPermissionAPIView.as_view()),
    path("user/", views.UserLoginOrReadOnly.as_view()),
    path("rate/", views.SendMessageAPIView.as_view()),
]
