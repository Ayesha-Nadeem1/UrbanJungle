import paho.mqtt.client as mqtt
import json
import logging
from datetime import datetime

import logging
from django.conf import settings

# Configure logging to match your Django setup
logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/mqtt_monitor.log',
            'formatter': 'verbose'
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'MQTT_Schedule_Monitor': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
})

logger = logging.getLogger("MQTT_Schedule_Monitor")

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to MQTT broker")
        client.subscribe("devices/+/light_schedule", qos=1)
    else:
        logger.error(f"Connection failed with code {rc}")

def on_message(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode('utf-8')
        
        if not payload:  # Handle deletion
            logger.info(f"Schedule cleared for {topic}")
            return
            
        data = json.loads(payload)
        logger.info(f"Received schedule update:\n"
                   f"Topic: {topic}\n"
                   f"Type: {data.get('type')}\n"
                   f"Timestamp: {data.get('timestamp')}\n"
                   f"Data: {json.dumps(data.get('data'), indent=2)}")
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")

def start_monitor():
    client = mqtt.Client(client_id="schedule_monitor")
    client.username_pw_set("admin", "ATmega32u")  # Use your credentials
    client.tls_set()  # Enable TLS
    
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        client.connect("5acf219d28014115bfe92ebe6f2afa31.s1.eu.hivemq.cloud", 8883)
        logger.info("Starting schedule monitor...")
        client.loop_forever()
    except Exception as e:
        logger.error(f"Monitor failed: {e}")
    finally:
        client.disconnect()

# if __name__ == "__main__":
#     start_monitor()