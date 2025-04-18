import os
import time
import logging
from threading import Thread
import django
import paho.mqtt.client as paho
from paho import mqtt

# Logging configuration
# logging.basicConfig(level=logging.INFO)


logging.basicConfig(
     level=logging.INFO,
     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
     handlers=[
         logging.FileHandler('/var/log/django/mqtt_debug.log'),
         logging.StreamHandler()
     ]
 )
logger = logging.getLogger(__name__)

def initialize_and_start_mqtt():
    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'UrbanJungle.settings')
        django.setup()

        from .models import Device, DeviceAuditLog
        from .utils import parse_and_save_device_data, safe_group_send, check_abnormalities, send_alert
        logger = logging.getLogger('mqtt')
        logger.setLevel(logging.INFO)

        client_id = f"device_subscriber_{int(time.time())}_{os.getpid()}"

        def broadcast_data(device_din, data):
            try:
                logger.debug(f"Broadcasting to {device_din}: {data}")
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
                logger.debug(f"✅ Broadcasted data to device {device_din}")
            except Exception as e:
                logger.error(f"🚫 Broadcast error: {e}", exc_info=True)
                import traceback
                logger.error(f"Error details: {traceback.format_exc()}")

        def on_message(client, userdata, msg):
            try:
                payload = msg.payload.decode('utf-8')
                logger.info(f"📨 Received MQTT message: {payload}")

                if not payload or '$' not in payload:
                    logger.warning("🚫 Invalid message format")
                    return

                audit_log = parse_and_save_device_data(payload)
                if audit_log and audit_log.device:
                    data = {
                        'temperature': audit_log.temperature,
                        'humidity': audit_log.humidity,
                        'tds': audit_log.tds,
                        'water_temperature': audit_log.water_temperature,
                        'timestamp': audit_log.timestamp
                    }

                    warnings = check_abnormalities(data)
                    if warnings:
                        message = "\n".join(warnings)
                        send_alert(audit_log.device.din, message)
                        data['warnings'] = warnings

                    broadcast_data(audit_log.device.din, data)

            except Exception as e:
                logger.error(f"🚫 Error processing message: {e}", exc_info=True)

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                logger.info("✅ Connected to MQTT broker")
                client.subscribe("devices/#", qos=1)
            else:
                logger.error(f"🚫 MQTT connection failed with code: {rc}")
                if rc not in [4, 5]:
                    time.sleep(min(2**client._reconnect_attempts, 30))
                    try:
                        client.reconnect()
                    except Exception as e:
                        logger.error(f"🚫 Reconnection failed: {e}", exc_info=True)

        def on_subscribe(client, userdata, mid, granted_qos, properties=None):
            logger.info(f"Subscribed with QoS: {granted_qos}")

        def on_disconnect(client, userdata, rc, properties=None):
            if rc != 0:
                logger.warning(f"Unexpected disconnect (rc: {rc}), reconnecting...")
                time.sleep(5)
                client.reconnect()

        def start_client():
            #while True:
            try:
                client = paho.Client(client_id=client_id, clean_session=True)
                client.tls_set(tls_version=mqtt.client.ssl.PROTOCOL_TLS,cert_reqs=mqtt.client.ssl.CERT_REQUIRED)
                client.tls_insecure_set(True)  # Disable strict certificate checks (for dev)
                client.username_pw_set("admin", "ATmega32u")

                client.on_connect = on_connect
                client.on_subscribe = on_subscribe
                client.on_message = on_message
                client.on_disconnect = on_disconnect

                logger.info(f"🔌 Connecting as {client_id}...")
                client.connect("5acf219d28014115bfe92ebe6f2afa31.s1.eu.hivemq.cloud", 8883, keepalive=60)
                client.loop_forever()

            except Exception as e:
                logger.error(f"🚫 Client loop error: {e}", exc_info=True)
                if 'client' in locals():
                    client.disconnect()
                #time.sleep(10)

        if not hasattr(initialize_and_start_mqtt, '_mqtt_thread'):
            initialize_and_start_mqtt._mqtt_thread = Thread(
                target=start_client,
                daemon=True,
                name=f"MQTT_{client_id}"
            )
            initialize_and_start_mqtt._mqtt_thread.start()
            logger.info("MQTT client thread started")
        else:
            logger.warning("MQTT client already running - skipping initialization") 

    except Exception as e:
        logger.error(f"🚫 MQTT initialization failed: {e}", exc_info=True)
        raise
