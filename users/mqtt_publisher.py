import paho.mqtt.client as paho
from paho import mqtt
import time
from datetime import datetime
import random
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
BROKER = "5acf219d28014115bfe92ebe6f2afa31.s1.eu.hivemq.cloud"
PORT = 8883
USERNAME = "admin"
PASSWORD = "ATmega32u"
TOPIC = "devices/data"

def generate_device_data(device_din):
    """Generate sample device data"""
    return (
        f"{device_din}$"
        f"{round(random.uniform(15.0, 30.0), 1)}$"  # temperature
        f"{round(random.uniform(40.0, 80.0), 1)}$"  # humidity
        f"{random.randint(100, 1000)}$"            # tds
        f"{round(random.uniform(15.0, 25.0), 1)}$" # water temp
        f"{'E00' if random.random() < 0.9 else 'E01'}$_"  # error code
    )

def main():
    client = paho.Client(client_id="device_publisher", clean_session=True)
    client.tls_set(tls_version=mqtt.client.ssl.PROTOCOL_TLS)
    client.username_pw_set(USERNAME, PASSWORD)

    device_din = "000023"  # Replace with actual DIN for testing

    try:
        client.connect(BROKER, PORT, keepalive=60)
        client.loop_start()

        while True:
            data = generate_device_data(device_din)
            client.publish(TOPIC, data, qos=1)
            logger.info(f"Published: {data}")
            time.sleep(60)  # Send every minute
            
    except KeyboardInterrupt:
        logger.info("Stopping publisher...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()