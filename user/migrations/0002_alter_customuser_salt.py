# Generated by Django 4.1.8 on 2023-05-17 12:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='salt',
            field=models.BinaryField(editable=True),
        ),
    ]