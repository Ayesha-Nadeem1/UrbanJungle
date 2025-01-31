from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

def send_notification(user, message):
    """
    Sends a WebSocket notification to the user using Django Channels.
    
    Args:
        user: The user to whom the notification should be sent.
        message: The notification message content.
    """
    channel_layer = get_channel_layer()
    group_name = f"user_{user.id}"  # Assuming you have a WebSocket group per user.

    # Send the message to the WebSocket group
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": "notification.message",
            "message": message,
        },
    )
