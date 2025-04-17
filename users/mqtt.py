import os
import time
import json
from threading import Thread
import django
import paho.mqtt.client as paho
from paho import mqtt
from datetime import datetime
import logging
from django.utils.timezone import now

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('mqtt')

def initialize_and_start_mqtt():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Dashboard.settings')
    django.setup()
    
    from .models import Device, DeviceAuditLog
    from .utils import parse_and_save_device_data, safe_group_send,check_abnormalities,send_notification

    # Generate unique client ID
    client_id = f"device_subscriber_{int(time.time())}_{os.getpid()}"

    def broadcast_data(device_din, data):
        """Broadcast data to WebSocket group"""
        try:
            # Convert datetime fields to ISO format
            if 'timestamp' in data:
                data['timestamp'] = data['timestamp'].isoformat()
                
            safe_group_send(
                f"device_{device_din}",
                {
                    "type": "send_device_data",
                    "data": data,
                    "message": "New device data received"
                }
            )
            logger.debug(f"Broadcasted to device {device_din}")
        except Exception as e:
            logger.error(f"Broadcast error: {str(e)}")
            pass

    # def on_message(client, userdata, msg):
    #     try:
    #         payload = msg.payload.decode('utf-8')
    #         # logger.info(f"Received: {payload}")
            
    #         if not payload or '$' not in payload:
    #             # logger.warning("Invalid message format")
    #             return

    #         # Parse and save data
    #         audit_log = parse_and_save_device_data(payload)
    #         if audit_log:
    #             # Prepare data for WebSocket
    #             data = {
    #                 'temperature': audit_log.temperature,
    #                 'humidity': audit_log.humidity,
    #                 'tds': audit_log.tds,
    #                 'water_temperature': audit_log.water_temperature,
    #                 'error_codes': audit_log.error_codes,
    #                 'timestamp': audit_log.timestamp
    #             }
    #             broadcast_data(audit_log.device.din, data)

    #     except Exception as e:
    #         # logger.error(f"Message handling error: {str(e)}")
    #         pass
    # In your mqtt.py on_message handler
    def on_message(client, userdata, msg):
        try:
            payload = msg.payload.decode('utf-8')
            
            if not payload or '$' not in payload:
                return

            # Parse and save data
            audit_log = parse_and_save_device_data(payload)
            if audit_log and audit_log.device:
                # Prepare data
                data = {
                    'temperature': audit_log.temperature,
                    'humidity': audit_log.humidity,
                    'tds': audit_log.tds,
                    'water_temperature': audit_log.water_temperature,
                    'timestamp': audit_log.timestamp
                }
                
                # Check for abnormalities
                warnings = check_abnormalities(data)
                if warnings:
                    message = "\n".join(warnings)
                    send_notification(audit_log.device.din, message)
                    data['warnings'] = warnings
                
                broadcast_data(audit_log.device.din, data)

        except Exception as e:
            print(f"Message handling error: {str(e)}")


    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info("Connected to broker")
            client.subscribe("devices/#", qos=1)
        else:
            # logger.error(f"Connection failed with code: {rc}")
            if rc not in [4, 5]:  # Don't retry auth failures
                time.sleep(5)
                client.reconnect()

    def start_client():
        try:
            client = paho.Client(client_id=client_id, clean_session=True)
            client.tls_set(tls_version=mqtt.client.ssl.PROTOCOL_TLS)
            client.username_pw_set("admin", "ATmega32u")
            
            client.on_connect = on_connect
            client.on_message = on_message
            
            logger.info(f"Connecting as {client_id}...")
            client.connect("5acf219d28014115bfe92ebe6f2afa31.s1.eu.hivemq.cloud", 8883, keepalive=60)
            client.loop_forever()
            
        except Exception as e:
            logger.error(f"Client error: {str(e)}")
            pass

    # Start in a new thread if not already running
    if not hasattr(initialize_and_start_mqtt, '_mqtt_thread'):
        initialize_and_start_mqtt._mqtt_thread = Thread(
            target=start_client,
            daemon=True
        )
        initialize_and_start_mqtt._mqtt_thread.start()