from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("dispositivos", "0002_dispositivos_v2_inventory")]

    operations = [
        migrations.AddField(model_name="dispositivo", name="availability_failures", field=models.PositiveSmallIntegerField(default=0)),
        migrations.AddField(model_name="dispositivo", name="availability_checked_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="redediscovery", name="monitored", field=models.BooleanField(default=False)),
        migrations.AddField(model_name="redediscovery", name="last_probe", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="redediscovery", name="last_probe_error", field=models.CharField(blank=True, default="", max_length=500)),
        migrations.CreateModel(
            name="MonitorDispositivos",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("enabled", models.BooleanField(default=False)),
                ("interval_minutes", models.PositiveSmallIntegerField(default=3)),
                ("last_attempt", models.DateTimeField(blank=True, null=True)),
            ],
        ),
    ]
