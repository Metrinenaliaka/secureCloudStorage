# Generated by Django 5.2 on 2025-04-22 07:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('storage', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='encryption_key',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
