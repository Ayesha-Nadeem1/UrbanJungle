from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'UrbanJungle.settings')

app = Celery('UrbanJungle')

# Configure Celery to use Redis as the broker
app.conf.broker_url = 'redis://redis:6379/0'  # Update if necessary

# Load task modules from all registered Django app configs
app.config_from_object('django.conf:settings', namespace='CELERY')

# Automatically discover tasks in all registered Django apps
app.autodiscover_tasks()

# Configure Celery Beat scheduler
app.conf.beat_scheduler = 'django_celery_beat.schedulers.DatabaseScheduler'

# Celery Beat Schedule Configuration
app.conf.beat_schedule = {
    'notify-fruiting-stage': {
        'task': 'users.tasks.notify_fruiting_stage',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=0, hour='*'),  # Runs every day at 8:00 AM
    },
    'notify-due-tasks': {
        'task': 'users.tasks.notify_due_tasks',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=0, hour='*'),  # Runs every day at 9:00 AM
    },
    'send-harvest-notifications': {
        'task': 'users.tasks.send_harvest_notifications',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=0, hour='*'),  # Runs every day at 12:00 PM
    },
    'update-pod-status': {
        'task': 'users.tasks.update_pod_status',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=0, hour='*'),  # Runs every day at 5:00 AM
    },
    'check-pods-for-harvest': {
        'task': 'users.tasks.check_pods_for_harvest',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=0, hour='*'),  # Runs every day at 6:00 AM
    },
    'check-past-logs-for-abnormalities': {
        'task': 'users.tasks.check_past_logs_for_abnormalities',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=0, hour='*'),  # Runs every hour
    },
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
