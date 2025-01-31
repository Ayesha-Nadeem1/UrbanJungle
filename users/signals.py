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
