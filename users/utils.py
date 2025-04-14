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


from datetime import timedelta,datetime, timezone
from django.conf import settings
import jwt

def generate_access_token(user_id):
    access_token_lifetime = settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME', timedelta(minutes=15))
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + access_token_lifetime,
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def generate_refresh_token(user_id):
    refresh_token_lifetime = settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME', timedelta(days=7))
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + refresh_token_lifetime,
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Token is invalid


from .models import Device, DeviceAuditLog
from django.utils.timezone import now

def parse_and_save_device_data(data_string):
    """
    Parses incoming IoT device data and saves it in the DeviceAuditLog model.
    Expected format: device_din$temperature$humidity$tds$water_temperature$error_codes$_
    """
    try:
        # Remove trailing `_` and split by `$`
        #print(data_string)
        data_parts = data_string.rstrip('_').split('$')
        #print(data_parts)
        #print(len(data_parts))
        
        if len(data_parts) < 6:
            raise ValueError("Incomplete data received.")

        # Extract fields
        device_din, temperature, humidity, tds, water_temperature, error_codes = data_parts
        
        # Find device by DIN
        device = Device.objects.filter(din=device_din).first()

        if not device:
            print(f"Device with DIN {device_din} not found.")  # Debugging log
            return None  # Exit early if no device is found

        # Save the data in the DeviceAuditLog
        audit_log = DeviceAuditLog.objects.create(
            device=device,
            temperature=float(temperature) if temperature else None,
            humidity=float(humidity) if humidity else None,
            tds=tds if tds else None,
            water_temperature=water_temperature if water_temperature else None,
            error_codes=error_codes if error_codes else None,
            timestamp=now()
        )

        return audit_log

    except Exception as e:
        print(f"Error parsing device data: {e}")
        return None

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import time

def safe_group_send(group_name, message):
    """Safe wrapper for group_send that handles timedelta expiry issues"""
    channel_layer = get_channel_layer()
    
    # Store the original expiry value
    original_expiry = getattr(channel_layer, 'expiry', None)
    
    try:
        # If expiry is a timedelta, convert it to seconds
        if hasattr(original_expiry, 'total_seconds'):
            channel_layer.expiry = int(original_expiry.total_seconds())
        
        # Send the message
        async_to_sync(channel_layer.group_send)(group_name, message)
    finally:
        # Restore the original expiry value
        if original_expiry is not None:
            channel_layer.expiry = original_expiry