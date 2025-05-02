from django.apps import AppConfig
import os
import threading
import logging

logger = logging.getLogger('users')

class UsersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "users"

    def ready(self):
        import users.signals

        # Prevent double-threading in Django dev server
        if os.environ.get('RUN_MAIN') == 'true':
            try:
                from users.mqtt import initialize_and_start_mqtt
                from users.mqtt_LS_monitor import start_monitor

                mqtt_thread = threading.Thread(
                    target=initialize_and_start_mqtt,
                    daemon=True,
                    name="MQTT_Thread"
                )
                mqtt_thread.start()
                logger.info("✅ MQTT client initialized in background thread")

                mqtt_thread2 = threading.Thread(
                    target=start_monitor,
                    daemon=True,
                    name="MQTT_Thread2"
                )
                mqtt_thread2.start()
                logger.info("✅ MQTT LS monitor initialized in background thread")

                
            except ImportError as e:
                logger.error(f"🚫 ImportError while starting MQTT: {e}")
            except Exception as e:
                logger.error(f"🚫 Unexpected error in MQTT initialization: {e}", exc_info=True)
