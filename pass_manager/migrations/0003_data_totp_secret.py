# Generated by Django 4.1.8 on 2023-05-17 17:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pass_manager', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='data',
            name='totp_secret',
            field=models.CharField(default='11', max_length=100),
            preserve_default=False,
        ),
    ]
