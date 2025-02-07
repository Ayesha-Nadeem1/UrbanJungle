# Generated by Django 4.2 on 2025-01-31 10:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0021_todo_created_for_device_todo_created_for_pod'),
    ]

    operations = [
        migrations.AddField(
            model_name='crop',
            name='max_optimal_water_temperature',
            field=models.TextField(default=30, help_text='water temperature needed'),
        ),
        migrations.AddField(
            model_name='crop',
            name='min_optimal_water_temperature',
            field=models.TextField(default=15, help_text='water temperature needed'),
        ),
    ]
