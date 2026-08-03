from django.urls import path
from . import api_views

urlpatterns = [
    path("scan/",       api_views.network_scan,      name="network_scan"),
    path("rename/",     api_views.rename_device,     name="rename_device"),
    path("me/",         api_views.me,                name="me"),
    path("system/",     api_views.system_info,       name="system_info"),
    path("interfaces/", api_views.network_interfaces, name="network_interfaces"),
]