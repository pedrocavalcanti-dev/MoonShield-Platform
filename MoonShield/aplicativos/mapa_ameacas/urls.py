from django.urls import path
from . import views

app_name = 'mapa_ameacas'

urlpatterns = [
    path('', views.mapa_view, name='mapa'),
    path('api/overview/', views.api_map_overview, name='api_map_overview'),
    path('api/feed/', views.api_map_feed, name='api_map_feed'),
    path('api/facets/', views.api_map_facets, name='api_map_facets'),
    path('api/search/', views.api_map_search, name='api_map_search'),
    path('api/location/', views.api_set_location, name='api_set_location'),
    path('api/location/geocode/', views.api_geocode, name='api_geocode'),
]
