from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'UrbanJungle.settings')

app = Celery('UrbanJungle')

# Configure Celery to use Redis as the broker
app.conf.broker_url = 'redis://redis:6379/0'  # 'redis' is the service name in your docker-compose

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# Namespace 'CELERY' means all celery-related config keys
# should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
