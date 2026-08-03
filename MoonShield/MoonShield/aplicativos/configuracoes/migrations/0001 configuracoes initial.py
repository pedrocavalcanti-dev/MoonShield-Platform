from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ConfigSistema",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("modo", models.CharField(choices=[("demo", "Demo / Mock"), ("prod", "Produção")], default="demo", max_length=10)),
                ("node_name", models.CharField(blank=True, default="JG-NODE-01", max_length=64)),
                ("node_ambiente", models.CharField(choices=[("lab", "LAB"), ("prod", "Produção")], default="lab", max_length=10)),
                ("node_tag", models.CharField(blank=True, default="", max_length=128)),
                ("node_desc", models.CharField(blank=True, default="", max_length=255)),
                ("cidr", models.CharField(blank=True, default="192.168.0.0/24", max_length=32)),
                ("gateway", models.CharField(blank=True, default="192.168.0.1", max_length=64)),
                ("dns1", models.CharField(blank=True, default="1.1.1.1", max_length=64)),
                ("dns2", models.CharField(blank=True, default="8.8.8.8", max_length=64)),
                ("ips_criticos", models.TextField(blank=True, default="")),
                ("excluir_scan", models.CharField(blank=True, default="", max_length=512)),
                ("iface_principal", models.CharField(blank=True, default="", max_length=64)),
                ("scan_interval", models.IntegerField(default=60)),
                ("ping_timeout", models.IntegerField(default=1000)),
                ("max_hosts", models.IntegerField(default=254)),
                ("scan_method", models.CharField(default="ping_arp", max_length=32)),
                ("scan_hostname", models.BooleanField(default=True)),
                ("scan_mac", models.BooleanField(default=True)),
                ("scan_oui", models.BooleanField(default=True)),
                ("ret_devices", models.IntegerField(default=30)),
                ("ret_logs", models.IntegerField(default=7)),
                ("ret_dns", models.IntegerField(default=7)),
                ("ret_incidents", models.IntegerField(default=90)),
                ("dns_enabled", models.BooleanField(default=False)),
                ("ids_enabled", models.BooleanField(default=False)),
                ("fw_enabled", models.BooleanField(default=False)),
                ("adguard_url", models.CharField(blank=True, default="", max_length=255)),
                ("adguard_user", models.CharField(blank=True, default="", max_length=80)),
                ("adguard_pass", models.CharField(blank=True, default="", max_length=120)),
                ("adguard_https", models.BooleanField(default=False)),
                ("adguard_interval", models.IntegerField(default=30)),
                ("adguard_mode", models.CharField(default="mock", max_length=16)),
                ("suricata_mode", models.CharField(default="mock", max_length=16)),
                ("suricata_eve_path", models.CharField(blank=True, default="/var/log/suricata/eve.json", max_length=255)),
                ("suricata_interval", models.IntegerField(default=5)),
                ("suricata_min_severity", models.IntegerField(default=2)),
                ("fw_mode", models.CharField(default="mock", max_length=16)),
                ("fw_target", models.CharField(default="local", max_length=16)),
                ("fw_host", models.CharField(blank=True, default="", max_length=255)),
                ("fw_token", models.CharField(blank=True, default="", max_length=255)),
                ("session_expiry", models.IntegerField(default=480)),
                ("max_login_attempts", models.IntegerField(default=5)),
                ("force_https", models.BooleanField(default=False)),
                ("access_log", models.BooleanField(default=True)),
                ("ip_ban", models.BooleanField(default=True)),
                ("log_level", models.CharField(
                    choices=[("DEBUG", "DEBUG"), ("INFO", "INFO"), ("WARNING", "WARNING"), ("ERROR", "ERROR")],
                    default="INFO", max_length=10,
                )),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Configuração do Sistema",
                "verbose_name_plural": "Configurações do Sistema",
            },
        ),
    ]