from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("configuracoes", "0005_alter_configsistema_adguard_mode_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="configsistema",
            name="appliance_onboarding_completo",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="configsistema",
            name="appliance_onboarding_concluido_em",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
