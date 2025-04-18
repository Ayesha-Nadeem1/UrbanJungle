# Generated by Django 4.2 on 2025-04-18 09:20

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0028_cartitem_is_selected'),
    ]

    operations = [
        migrations.CreateModel(
            name='Blog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('image', models.ImageField(blank=True, null=True, upload_to='blog_images/')),
                ('body', models.TextField()),
                ('category', models.CharField(max_length=100)),
                ('date_published', models.DateTimeField(auto_now_add=True)),
                ('reading_time', models.PositiveIntegerField(help_text='Estimated reading time in minutes')),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='blogs', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
