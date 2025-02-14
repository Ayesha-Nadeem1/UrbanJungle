import json
from channels.generic.websocket import AsyncWebsocketConsumer
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.contrib.auth import get_user_model
from asgiref.sync import sync_to_async

User = get_user_model()

class BaseAuthenticatedConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """Authenticate user via JWT and connect to the WebSocket group."""
        self.user = await self.authenticate_user()
        if not self.user:
            await self.close(code=4001)  # Unauthorized access
            return

        self.group_name = self.get_group_name()
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        """Remove the user from the WebSocket group on disconnect."""
        if not hasattr(self, "group_name"):
            self.group_name = self.get_group_name()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def authenticate_user(self):
        """Extract and verify JWT token from the WebSocket headers."""
        headers = dict(self.scope.get("headers", []))
        token = headers.get(b"authorization", None)

        if not token:
            return None

        try:
            token_str = token.decode("utf-8").split(" ")[1]  # Remove "Bearer" prefix
            decoded_token = UntypedToken(token_str).payload
            user_id = decoded_token.get("user_id")
            return await sync_to_async(User.objects.get)(id=user_id)
        except (User.DoesNotExist, TokenError, InvalidToken, IndexError):
            return None

    def get_group_name(self):
        """To be implemented by subclasses to define group naming logic."""
        raise NotImplementedError("Subclasses must define `get_group_name` method.")


class PlantStatusConsumer(BaseAuthenticatedConsumer):
    def get_group_name(self):
        device_id = self.scope['url_route']['kwargs']['device_id']
        return f"plant_status_{device_id}"

    async def send_status_update(self, event):
        await self.send(text_data=json.dumps(event['data']))


class TodoNotificationConsumer(BaseAuthenticatedConsumer):
    def get_group_name(self):
        return f"user_notifications_{self.user.id}"

    async def send_task_notification(self, event):
        await self.send(text_data=json.dumps(event['data']))


class HarvestNotificationConsumer(BaseAuthenticatedConsumer):
    def get_group_name(self):
        return f"user_{self.user.id}"

    async def notification_message(self, event):
        message = event["message"]
        await self.send(text_data=json.dumps({"notification": message}))
