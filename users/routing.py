from django.urls import path
from .consumers import (
    PlantStatusConsumer,
    TodoNotificationConsumer,
    HarvestNotificationConsumer,
    DeviceNotificationConsumer,
    DeviceDataConsumer,
    AlertNotificationConsumer
)
# websocket_urlpatterns = [
#     path('ws/plant-status/<int:device_id>/', PlantStatusConsumer.as_asgi()),
#     path('ws/todo-notifications/', TodoNotificationConsumer.as_asgi()),
#     path('ws/harvest-notifications/', HarvestNotificationConsumer.as_asgi()),
#     path("ws/device-notifications/", DeviceNotificationConsumer.as_asgi()),
#     path("ws/device/<str:din>/", DeviceDataConsumer.as_asgi()),
#     path("ws/alerts/<str:din>/", AlertNotificationConsumer.as_asgi())
# ]

websocket_urlpatterns = [
    path('ws/plant-status/<int:device_id>/<str:token>/', PlantStatusConsumer.as_asgi()),
    path('ws/todo-notifications/<str:token>/', TodoNotificationConsumer.as_asgi()),
    path('ws/harvest-notifications/<str:token>/', HarvestNotificationConsumer.as_asgi()),
    path('ws/device-notifications/<str:token>/', DeviceNotificationConsumer.as_asgi()),
    path('ws/device/<str:din>/<str:token>/', DeviceDataConsumer.as_asgi()),
    path('ws/alerts/<str:din>/<str:token>/', AlertNotificationConsumer.as_asgi()),
]