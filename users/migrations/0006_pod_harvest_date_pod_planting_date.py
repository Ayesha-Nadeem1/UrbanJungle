# Generated by Django 4.2 on 2025-01-17 10:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_crop_required_light_duration_alter_crop_life_cycle'),
    ]

    operations = [
        migrations.AddField(
            model_name='pod',
            name='harvest_date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='pod',
            name='planting_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
