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

# notifications.py
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import logging
from django.utils.timezone import now

logger = logging.getLogger(__name__)

def send_alert(device_din, message):
    """
    Send notification to specific device's alert channel
    
    Args:
        device_din: Device DIN to send alert to
        message: Notification message
    """
    try:
        channel_layer = get_channel_layer()
        
        async_to_sync(channel_layer.group_send)(
            f"alerts_{device_din}",
            {
                "type": "send_alert",
                "message": message,
                "timestamp": now().isoformat()
            }
        )
        
        logger.info(f"Alert sent to device {device_din}: {message}")
        
    except Exception as e:
        logger.error(f"Failed to send alert: {str(e)}")


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


# utils.py
from django.core.exceptions import ObjectDoesNotExist
from .models import Crop

def check_abnormalities(sensor_data):
    """
    Check for abnormalities in sensor readings using global crop thresholds.
    
    Args:
        sensor_data: Dictionary containing sensor readings with keys:
            - temperature (float)
            - humidity (float)
            - tds (str/float)
            - water_temperature (str/float)
            
    Returns:
        list: List of warning messages if abnormalities found, empty list otherwise
    """
    warnings = []
    
    try:
        # Get global crop thresholds (first crop in DB)
        crop = Crop.objects.first()
        if not crop:
            return warnings  # No crop data available

        # Check temperature
        if 'temperature' in sensor_data and sensor_data['temperature'] is not None:
            temp = sensor_data['temperature']
            if temp < crop.min_optimal_temperature:
                warnings.append(f"Low Temperature Alert: {temp}°C (Min: {crop.min_optimal_temperature}°C)")
            elif temp > crop.max_optimal_temperature:
                warnings.append(f"High Temperature Alert: {temp}°C (Max: {crop.max_optimal_temperature}°C)")

        # Check humidity
        if 'humidity' in sensor_data and sensor_data['humidity'] is not None:
            humidity = sensor_data['humidity']
            if humidity < crop.min_optimal_humidity:
                warnings.append(f"Low Humidity Alert: {humidity}% (Min: {crop.min_optimal_humidity}%)")
            elif humidity > crop.max_optimal_humidity:
                warnings.append(f"High Humidity Alert: {humidity}% (Max: {crop.max_optimal_humidity}%)")

        # Check TDS
        if 'tds' in sensor_data and sensor_data['tds'] is not None:
            try:
                tds = float(sensor_data['tds'])
                if tds < float(crop.min_optimal_tds):
                    warnings.append(f"Low TDS Alert: {tds} (Min: {crop.min_optimal_tds})")
                elif tds > float(crop.max_optimal_tds):
                    warnings.append(f"High TDS Alert: {tds} (Max: {crop.max_optimal_tds})")
            except (ValueError, TypeError):
                pass

        # Check Water Temperature
        if 'water_temperature' in sensor_data and sensor_data['water_temperature'] is not None:
            try:
                water_temp = float(sensor_data['water_temperature'])
                if water_temp < float(crop.min_optimal_water_temperature):
                    warnings.append(f"Low Water Temperature Alert: {water_temp}°C (Min: {crop.min_optimal_water_temperature}°C)")
                elif water_temp > float(crop.max_optimal_water_temperature):
                    warnings.append(f"High Water Temperature Alert: {water_temp}°C (Max: {crop.max_optimal_water_temperature}°C)")
            except (ValueError, TypeError):
                pass

    except Exception as e:
        print(f"Error checking abnormalities: {e}")
    
    return warnings

