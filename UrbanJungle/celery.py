from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'UrbanJungle.settings')

app = Celery('UrbanJungle')

# Configure Celery to use Redis as the broker
app.conf.broker_url = 'redis://redis-server:6379/0'  # Update if necessary

# Load task modules from all registered Django app configs
app.config_from_object('django.conf:settings', namespace='CELERY')

# Automatically discover tasks in all registered Django apps
app.autodiscover_tasks()
app.autodiscover_tasks(['users'])


# Configure Celery Beat scheduler
app.conf.beat_scheduler = 'django_celery_beat.schedulers.DatabaseScheduler'

# Celery Beat Schedule Configuration
app.conf.beat_schedule = {
    'notify-fruiting-stage': {
        'task': 'users.tasks.notify_fruiting_stage',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=10, hour='12'),
    },
    'notify-due-tasks': {
        'task': 'users.tasks.notify_due_tasks',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=20, hour='12'),
    },
    'send-harvest-notifications': {
        'task': 'users.tasks.send_harvest_notifications',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=30, hour='12'),
    },
    'update-pod-status': {
        'task': 'users.tasks.update_pod_status',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=40, hour='12'),  
        #'schedule': 120.0, 
    },
    'check-pods-for-harvest': {
        'task': 'users.tasks.check_pods_for_harvest',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=50, hour='12'),  
    },
    'check-past-logs-for-abnormalities': {
        'task': 'users.tasks.check_past_logs_for_abnormalities',  # Replace 'your_app' with your actual app name
        'schedule': crontab(minute=0, hour='*'),  
    },
    # 'test_task': {
    #     'task': 'users.tasks.test_task',  # Replace 'your_app' with your actual app name
    #     'schedule': 60.0,  # Run every 60 seconds  
    # },
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
