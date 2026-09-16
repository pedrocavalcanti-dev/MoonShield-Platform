from django.db import migrations, models


def converter_modos_legados(apps, schema_editor):
    ConfigSistema = apps.get_model("configuracoes", "ConfigSistema")
    ConfigSistema.objects.exclude(modo="prod").update(modo="prod")


class Migration(migrations.Migration):
    dependencies = [("configuracoes", "0007_configsistema_appliance_onboarding_etapa")]

    operations = [
        migrations.RunPython(converter_modos_legados, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="configsistema",
            name="modo",
            field=models.CharField(
                choices=[("prod", "Operacional")],
                default="prod",
                help_text="Compatibilidade administrativa; a appliance usa somente telemetria real.",
                max_length=10,
            ),
        ),
    ]
