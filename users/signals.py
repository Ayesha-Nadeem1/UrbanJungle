from django.db.models.signals import post_save
from django.dispatch import receiver
from datetime import timedelta
from django.utils.timezone import now
from .models import Pod, Todo

@receiver(post_save, sender=Pod)
def create_todo_for_harvest(sender, instance, created, **kwargs):
    """
    Signal handler to create a Todo when a Pod reaches its harvesting stage.
    """
    if instance.harvest_start_date and now().date() >= instance.harvest_start_date:
        # Check if a Todo already exists for this Pod and harvest cycle
        existing_todo = Todo.objects.filter(
            created_for_pod=instance,
            due_date=instance.harvest_end_date,
            task_description=f"Harvest {instance.crop.name} in Pod {instance.pod_number}"
        ).exists()

        if not existing_todo:
            # Create a new Todo
            Todo.objects.create(
                created_for_device=instance.device,
                created_for_pod=instance,
                due_date=instance.harvest_end_date,
                priority="high",
                task_description=f"Harvest {instance.crop.name} in Pod {instance.pod_number}"
            )


from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import DeviceAuditLog, Crop
from .utils import send_notification

@receiver(post_save, sender=DeviceAuditLog)
def check_abnormalities(sender, instance, **kwargs):
    """
    Checks for abnormalities in sensor readings and sends notifications if necessary.
    """
    try:
        # Get global crop thresholds (assuming same for all crops)
        crop = Crop.objects.first()  # Adjust if crops have different conditions per device

        if not crop:
            return  # No crop data available to compare

        warnings = []

        # Check temperature
        if instance.temperature is not None:
            if instance.temperature < crop.min_optimal_temperature:
                warnings.append(f"Low Temperature Alert: {instance.temperature}°C (Min: {crop.min_optimal_temperature}°C)")
            elif instance.temperature > crop.max_optimal_temperature:
                warnings.append(f"High Temperature Alert: {instance.temperature}°C (Max: {crop.max_optimal_temperature}°C)")

        # Check humidity
        if instance.humidity is not None:
            if instance.humidity < crop.min_optimal_humidity:
                warnings.append(f"Low Humidity Alert: {instance.humidity}% (Min: {crop.min_optimal_humidity}%)")
            elif instance.humidity > crop.max_optimal_humidity:
                warnings.append(f"High Humidity Alert: {instance.humidity}% (Max: {crop.max_optimal_humidity}%)")

        # Check TDS
        if instance.tds is not None:
            if float(instance.tds) < float(crop.min_optimal_tds):
                warnings.append(f"Low TDS Alert: {instance.tds} (Min: {crop.min_optimal_tds})")
            elif float(instance.tds) > float(crop.max_optimal_tds):
                warnings.append(f"High TDS Alert: {instance.tds} (Max: {crop.max_optimal_tds})")

        # Check Water Temperature
        if instance.water_temperature is not None:
            if float(instance.water_temperature) < float(crop.min_optimal_water_temperature):
                warnings.append(f"Low Water Temperature Alert: {instance.water_temperature}°C (Min: {crop.min_optimal_water_temperature}°C)")
            elif float(instance.water_temperature) > float(crop.max_optimal_water_temperature):
                warnings.append(f"High Water Temperature Alert: {instance.water_temperature}°C (Max: {crop.max_optimal_water_temperature}°C)")

        # If any abnormalities exist, send notification
        if warnings:
            message = "\n".join(warnings)
            # Assuming each device belongs to a user
            user = instance.device.user if instance.device else None
            if user:
                send_notification(user, message)

    except Exception as e:
        print(f"Error checking abnormalities: {e}")
