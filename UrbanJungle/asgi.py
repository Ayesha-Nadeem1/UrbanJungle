import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from users.routing import websocket_urlpatterns
from channels.middleware.base import BaseMiddleware
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'UrbanJungle.settings')

class JWTAuthMiddleware(BaseMiddleware):
    """
    Custom WebSocket middleware for handling JWT authentication.
    """

    async def __init__(self, inner, scope):
        # Initialize the middleware
        await super().__init__(inner, scope)

        token = dict(self.scope.get('headers')).get(b'authorization', None)
        if token:
            token = token.decode('utf-8').split(' ')[1]  # Remove 'Bearer' prefix

        try:
            # Decode the token and set the user
            decoded_token = JWTAuthentication().get_validated_token(token)
            self.scope['user'] = JWTAuthentication().get_user(decoded_token)
        except (TokenError, InvalidToken):
            self.scope['user'] = None  # Invalid token

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})
