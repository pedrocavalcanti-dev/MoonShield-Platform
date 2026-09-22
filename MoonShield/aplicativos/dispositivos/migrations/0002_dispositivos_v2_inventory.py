from django.db import migrations, models


def _normalizar_mac(valor):
    texto = str(valor or "").strip().upper().replace("-", ":")
    partes = texto.split(":")
    if len(partes) != 6 or any(len(parte) != 2 for parte in partes):
        return None
    try:
        [int(parte, 16) for parte in partes]
    except ValueError:
        return None
    return ":".join(partes)


def preparar_identidades(apps, schema_editor):
    Dispositivo = apps.get_model("dispositivos", "Dispositivo")
    usados = set()
    for dispositivo in Dispositivo.objects.order_by("pk").iterator():
        mac = _normalizar_mac(dispositivo.mac)
        if mac:
            dispositivo.mac = mac
            chave = f"mac:{mac}"
        else:
            chave = f"legacy:ip:{dispositivo.current_ip}:{dispositivo.pk}"
        if chave in usados:
            chave = f"legacy:duplicate:{dispositivo.pk}"
        usados.add(chave)
        dispositivo.identity_key = chave
        dispositivo.identity_temporary = not bool(mac)
        dispositivo.save(update_fields=["mac", "identity_key", "identity_temporary"])


class Migration(migrations.Migration):
    dependencies = [("dispositivos", "0001_initial")]

    operations = [
        migrations.RenameField(model_name="dispositivo", old_name="ip", new_name="current_ip"),
        migrations.RenameField(model_name="dispositivo", old_name="hostname", new_name="detected_hostname"),
        migrations.RenameField(model_name="dispositivo", old_name="os", new_name="os_guess"),
        migrations.RenameField(model_name="dispositivo", old_name="tipo", new_name="device_type"),
        migrations.AlterField(model_name="dispositivo", name="current_ip", field=models.GenericIPAddressField(blank=True, db_index=True, null=True, protocol="IPv4")),
        migrations.AddField(model_name="dispositivo", name="identity_key", field=models.CharField(blank=True, max_length=180, null=True)),
        migrations.AddField(model_name="dispositivo", name="identity_temporary", field=models.BooleanField(default=True)),
        migrations.AddField(model_name="dispositivo", name="classification_confidence", field=models.PositiveSmallIntegerField(default=0)),
        migrations.AddField(model_name="dispositivo", name="observed_ports", field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name="dispositivo", name="interface_name", field=models.CharField(blank=True, default="", max_length=64)),
        migrations.AddField(model_name="dispositivo", name="network_role", field=models.CharField(blank=True, default="", max_length=20)),
        migrations.AddField(model_name="dispositivo", name="network_cidr", field=models.CharField(blank=True, default="", max_length=43)),
        migrations.AddField(model_name="dispositivo", name="network_id", field=models.CharField(blank=True, db_index=True, default="", max_length=128)),
        migrations.AddField(model_name="scanrun", name="requested_networks", field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name="scanrun", name="status", field=models.CharField(choices=[("running", "Em andamento"), ("completed", "Concluído"), ("partial", "Parcial"), ("failed", "Falhou")], default="running", max_length=20)),
        migrations.AddField(model_name="scanrun", name="origin", field=models.CharField(default="manual", max_length=32)),
        migrations.AddField(model_name="scanrun", name="errors_by_network", field=models.JSONField(blank=True, default=dict)),
        migrations.AddField(model_name="scanrun", name="summary", field=models.JSONField(blank=True, default=dict)),
        migrations.AddField(model_name="scanrun", name="lock_key", field=models.CharField(blank=True, max_length=64, null=True, unique=True)),
        migrations.AlterField(model_name="scanrun", name="cidr", field=models.CharField(blank=True, default="", max_length=32)),
        migrations.CreateModel(
            name="RedeDiscovery",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("network_id", models.CharField(max_length=128, unique=True)),
                ("role", models.CharField(max_length=20)),
                ("interface_name", models.CharField(max_length=64)),
                ("cidr", models.CharField(max_length=43)),
                ("selected", models.BooleanField(default=False)),
                ("last_scan", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["role", "interface_name"]},
        ),
        migrations.RunPython(preparar_identidades, migrations.RunPython.noop),
        migrations.AlterField(model_name="dispositivo", name="identity_key", field=models.CharField(db_index=True, max_length=180, unique=True)),
        migrations.AlterField(model_name="dispositivo", name="status", field=models.CharField(choices=[("online", "Online"), ("offline", "Offline"), ("stale", "Desatualizado"), ("unknown", "Desconhecido")], db_index=True, default="unknown", max_length=20)),
    ]
