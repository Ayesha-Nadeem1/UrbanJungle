# Generated by Django 4.2 on 2025-01-26 17:55

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0020_remove_todo_created_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='todo',
            name='created_for_device',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='device', to='users.device'),
        ),
        migrations.AddField(
            model_name='todo',
            name='created_for_pod',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='pod', to='users.pod'),
        ),
    ]
