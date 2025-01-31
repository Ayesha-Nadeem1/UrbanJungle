from django.urls import path
from .consumers import PlantStatusConsumer,TodoNotificationConsumer,HarvestNotificationConsumer

websocket_urlpatterns = [
    path('ws/plant-status/', PlantStatusConsumer.as_asgi()),
    path('ws/todo-notifications/', TodoNotificationConsumer.as_asgi()),
    path('ws/harvest-notifications/', HarvestNotificationConsumer.as_asgi()),
]
