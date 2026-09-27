# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('configuracoes', '0009_configsistema_node_location'),
    ]

    operations = [
        migrations.AddField(
            model_name='configsistema',
            name='mapbox_access_token',
            field=models.CharField(blank=True, default='', max_length=512),
        ),
    ]
