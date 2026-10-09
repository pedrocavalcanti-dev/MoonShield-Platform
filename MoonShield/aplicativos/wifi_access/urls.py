from django.urls import include, path

from . import views


app_name = "wifi"

urlpatterns = [
    path("", views.panel, name="panel"),
    path("api/", include("wifi_access.api.urls")),
    path("panel-api/state/", views.panel_state, name="panel_state"),
    path("panel-api/trusted/", views.trusted_devices, name="trusted_devices"),
    path("panel-api/trusted/<int:device_id>/", views.trusted_device_detail, name="trusted_device_detail"),
    path("panel-api/trusted/<int:device_id>/deactivate/", views.deactivate_trusted_device, name="deactivate_trusted_device"),
    path("panel-api/authorizations/<int:authorization_id>/revoke/", views.revoke_authorization, name="revoke_authorization"),
    path("panel-api/trusted/bulk/", views.bulk_trusted_devices, name="bulk_trusted_devices"),
    path("panel-api/trusted/bulk-action/", views.bulk_trusted_action, name="bulk_trusted_action"),
    path("panel-api/diagnostics/", views.diagnostics_data, name="diagnostics_data"),
    path("panel-api/sync-now/", views.sync_now, name="sync_now"),
]
