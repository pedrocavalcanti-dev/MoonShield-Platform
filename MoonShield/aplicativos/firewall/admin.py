# firewall/admin.py

from django.contrib import admin
from .models import (
    AllowlistEntry, BlocklistEntry, EventoFirewall,
    GeoblockEntry, NatEntry, RegraFirewall,
)


@admin.register(RegraFirewall)
class RegraFirewallAdmin(admin.ModelAdmin):
    list_display  = ('priority', 'action', 'iface', 'dir', 'proto', 'src', 'dst', 'port', 'desc', 'enabled')
    list_filter   = ('action', 'iface', 'dir', 'proto', 'enabled')
    search_fields = ('desc', 'src', 'dst', 'port')
    ordering      = ('priority',)


@admin.register(NatEntry)
class NatEntryAdmin(admin.ModelAdmin):
    list_display = ('name', 'iface', 'wan_port', 'lan_ip', 'lan_port', 'proto', 'enabled')
    list_filter  = ('iface', 'proto', 'enabled')


@admin.register(BlocklistEntry)
class BlocklistEntryAdmin(admin.ModelAdmin):
    list_display  = ('ip', 'reason', 'source', 'expires', 'criado_em')
    list_filter   = ('source',)
    search_fields = ('ip', 'reason')


@admin.register(AllowlistEntry)
class AllowlistEntryAdmin(admin.ModelAdmin):
    list_display  = ('ip', 'reason', 'criado_em')
    search_fields = ('ip', 'reason')


@admin.register(GeoblockEntry)
class GeoblockEntryAdmin(admin.ModelAdmin):
    list_display = ('country', 'code', 'dir', 'enabled')
    list_filter  = ('dir', 'enabled')


@admin.register(EventoFirewall)
class EventoFirewallAdmin(admin.ModelAdmin):
    list_display  = ('timestamp', 'acao', 'proto', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'iface', 'sensor')
    list_filter   = ('acao', 'proto', 'iface')
    search_fields = ('src_ip', 'dst_ip')
    readonly_fields = ('event_hash', 'raw_json', 'criado_em')
    date_hierarchy  = 'timestamp'