import json
from channels.generic.websocket import AsyncWebsocketConsumer
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken, AuthenticationFailed
from django.contrib.auth import get_user_model
from asgiref.sync import sync_to_async
from jwt import decode
from jwt.exceptions import ExpiredSignatureError
from jwt.exceptions import InvalidTokenError
from django.conf import settings

from rest_framework_simplejwt.authentication import JWTAuthentication
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from models import Device


def get_user_model_instance():
    return get_user_model()

User = get_user_model_instance()

class BaseAuthenticatedConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """Authenticate user via JWT and connect to the WebSocket group."""
        self.user = await self.authenticate_user()
        
        if not self.user:
            print("WebSocket authentication failed. Closing connection.")  # Debugging
            await self.close(code=4001)  # Unauthorized access
            return

        self.group_name = self.get_group_name()  # No need to await this
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        print(f"WebSocket connected: {self.user.username}")  # Debugging
        await self.accept()


    async def disconnect(self, close_code):
        """Safely remove the user from the WebSocket group on disconnect."""
        if not self.user:  # Ensure user is authenticated before accessing attributes
            return
        
        if hasattr(self, "group_name") and self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def authenticate_user(self):
        """Extract token from headers and authenticate user."""
        headers = dict(self.scope.get("headers", []))
        token_key = b"authorization"

        if token_key not in headers:
            print("WebSocket authentication failed: No token provided.")  # Debugging
            return None

        token = headers[token_key].decode().split(" ")[1]  # Assuming "Bearer <token>"
        print(token)

        try:
            payload = decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = await self.get_user(payload["user_id"])
            print(f"Authenticated WebSocket user: {user.username}")  # Debugging
            return user
        except ExpiredSignatureError:
            print("WebSocket authentication failed: Token expired.")
        except InvalidTokenError:
            print("WebSocket authentication failed: Invalid token.")
        except User.DoesNotExist:
            print("WebSocket authentication failed: User not found.")
        
        return None

    @sync_to_async
    def get_user(self, user_id):
        """Retrieve user synchronously in an async-safe way."""
        return User.objects.get(id=user_id)
    
    async def get_group_name(self):
        """Ensure user is authenticated before generating group name."""
        if not self.user:
            raise ValueError("User must be authenticated before getting group name.")
        return f"user_{self.user.id}"


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


# class HarvestNotificationConsumer(BaseAuthenticatedConsumer):
#     def get_group_name(self):
#         return f"user_{self.user.id}"

#     async def notification_message(self, event):
#         message = event["message"]
#         await self.send(text_data=json.dumps({"notification": message}))


class HarvestNotificationConsumer(BaseAuthenticatedConsumer):
    def get_group_name(self):
        return f"user_{self.user.id}"

    async def notification_message(self, event):
        message = event["message"]
        await self.send(text_data=json.dumps({"notification": message}))

    async def connect(self):
        """Authenticate user via JWT and connect to the WebSocket group."""
        await super().connect()  # Call the parent method for authentication and connection

        # Send a dummy message to the frontend after connecting
        dummy_message = {
            "message": "Welcome to harvest notifications! This is a test message."
        }
        await self.send(text_data=json.dumps(dummy_message))  # Send dummy data to the client

class DeviceNotificationConsumer(BaseAuthenticatedConsumer):
    def get_group_name(self):
        return f"user_device_notifications_{self.user.id}"

    async def send_device_notification(self, event):
        """Send a WebSocket notification when a new device is added."""
        await self.send(text_data=json.dumps(event["data"]))

import logging
logging.basicConfig(level=logging.INFO)

import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser
from .models import Device
import logging

logger = logging.getLogger(__name__)

class DeviceDataConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            self.device_din = self.scope['url_route']['kwargs'].get('din')
            await self.authenticate()
            
            if not self.user or self.user.is_anonymous:
                await self.close(code=4001)  # Unauthorized
                return

            if self.device_din and not await self.verify_device_ownership():
                await self.close(code=4003)  # Forbidden
                return

            self.group_name = f"device_{self.device_din}" if self.device_din else "all_devices"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            logger.info(f"Client connected to {self.group_name}")

        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            await self.close(code=4000)

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        logger.info(f"Client disconnected (code: {close_code})")

    async def send_device_data(self, event):
        """Handle device data broadcasts"""
        try:
            await self.send(text_data=json.dumps({
                "data": event["data"],
                "message": event["message"]
            }))
            logger.debug("Data sent successfully")
        except Exception as e:
            logger.error(f"Send error: {str(e)}")
            await self.close()

    @database_sync_to_async
    def authenticate(self):
        try:
            headers = dict(self.scope['headers'])
            auth_header = headers.get(b'authorization', b'').decode('utf-8')
            
            if not auth_header.startswith('Bearer '):
                raise ValueError("No Bearer token provided")
            
            token = auth_header.split(' ')[1].strip()
            auth = JWTAuthentication()
            validated_token = auth.get_validated_token(token)
            self.user = auth.get_user(validated_token)
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            self.user = AnonymousUser()
            raise

    @database_sync_to_async
    def verify_device_ownership(self):
        try:
            device = Device.objects.get(din=self.device_din)
            return device.owner == self.user
        except Device.DoesNotExist:
            return False