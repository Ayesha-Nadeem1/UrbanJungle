import json
from channels.generic.websocket import AsyncWebsocketConsumer

class PlantStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Accept the WebSocket connection
        await self.accept()

    async def disconnect(self, close_code):
        # Handle disconnection
        pass

    async def send_status_update(self, event):
        # Send plant status update to the frontend
        await self.send(text_data=json.dumps(event['data']))

class TodoNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Group name for the logged-in user
        self.group_name = f"user_notifications_{self.scope['user'].id}"

        # Add the user to the group
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # Remove the user from the group
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def send_task_notification(self, event):
        # Send task notification to the frontend
        await self.send(text_data=json.dumps(event['data']))

from channels.generic.websocket import AsyncWebsocketConsumer
import json

class HarvestNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]  # Assuming authentication middleware is used
        self.group_name = f"user_{self.user.id}"

        # Add the user to the WebSocket group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name,
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Remove the user from the WebSocket group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name,
        )

    async def notification_message(self, event):
        # Send the notification to the WebSocket
        message = event["message"]
        await self.send(text_data=json.dumps({"notification": message}))
