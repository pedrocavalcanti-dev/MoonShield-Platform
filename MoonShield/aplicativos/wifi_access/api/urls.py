from django.urls import path

from . import views


urlpatterns = [
    path("authorize/", views.authorize, name="authorize"),
    path("revoke/", views.revoke, name="revoke"),
    path("status/", views.status, name="status"),
]
