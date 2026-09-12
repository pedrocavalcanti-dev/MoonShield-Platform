from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("configuracoes", "0006_configsistema_appliance_onboarding"),
    ]

    operations = [
        migrations.AddField(
            model_name="configsistema",
            name="appliance_onboarding_etapa",
            field=models.PositiveSmallIntegerField(
                default=1,
                validators=[
                    MinValueValidator(1),
                    MaxValueValidator(10),
                ],
            ),
        ),
    ]
