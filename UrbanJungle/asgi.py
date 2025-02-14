import os
import jwt
from django.conf import settings
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.middleware.base import BaseMiddleware
from users.routing import websocket_urlpatterns
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from asgiref.sync import sync_to_async

User = get_user_model()

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "UrbanJungle.settings")

class JWTAuthMiddleware(BaseMiddleware):
    """
    Middleware to authenticate WebSocket connections using JWT.
    """

    async def __call__(self, scope, receive, send):
        headers = dict(scope["headers"])  # Convert headers to dictionary
        token = None

        if b"authorization" in headers:
            auth_header = headers[b"authorization"].decode("utf-8")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]  # Extract token

        if token:
            try:
                # Validate JWT token
                decoded_token = JWTAuthentication().get_validated_token(token)
                user = await self.get_user(decoded_token)
                scope["user"] = user  # Attach user to scope
            except (TokenError, InvalidToken):
                scope["user"] = None  # Set as anonymous user

        return await super().__call__(scope, receive, send)

    @sync_to_async
    def get_user(self, decoded_token):
        """Fetch user from the database based on JWT token"""
        try:
            user = User.objects.get(id=decoded_token["user_id"])
            return user
        except User.DoesNotExist:
            return None

# Apply JWT middleware to WebSockets
application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(),
        "websocket": JWTAuthMiddleware(
            AuthMiddlewareStack(
                URLRouter(websocket_urlpatterns)
            )
        ),
    }
)
