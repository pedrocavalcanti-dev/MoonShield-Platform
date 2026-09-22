from django.urls import path

from . import api_views

urlpatterns = [
    path("inventory/", api_views.get_inventory, name="get_inventory"),
    path("networks/", api_views.networks, name="networks"),
    path("scan/", api_views.network_scan, name="network_scan"),
    path("rename/", api_views.rename_device, name="rename_device"),
]
