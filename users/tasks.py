from celery import shared_task
from datetime import date, timedelta,datetime
from .models import Pod,Todo
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .utils import send_notification
from django.db.models import Q


channel_layer = get_channel_layer()

@shared_task
def notify_fruiting_stage():
    """
    Task to notify users when a plant enters the fruiting stage 
    and send pollination notifications during the first two weeks.
    """
    today = date.today()
    pods_in_fruiting_stage = Pod.objects.filter(fruiting_date__isnull=False)

    for pod in pods_in_fruiting_stage:
        # Calculate the number of days since the fruiting date
        days_since_fruiting = (today - pod.fruiting_date).days

        # Check if the plant is within the first two weeks of the fruiting stage
        if 0 <= days_since_fruiting < 14:
            crop_name = pod.crop.name
            pod_number = pod.pod_number
            device_id = pod.device.id
            message = "Plant is in fruiting stage, shake plant for pollination."

            # Send WebSocket notification
            async_to_sync(channel_layer.group_send)(
                f"plant_status_{device_id}",  # Group name based on device ID
                {
                    'type': 'send_status_update',
                    'data': {
                        'device_id': device_id,
                        'pod_number': pod_number,
                        'crop_name': crop_name,
                        'message': message,
                    },
                }
            )


@shared_task
def notify_due_tasks():
    """
    Task to notify users about their due tasks.
    """
    today = date.today()
    due_tasks = Todo.objects.filter(due_date=today, status='pending')

    channel_layer = get_channel_layer()  # Get the channel layer instance

    for task in due_tasks:
        # Ensure you have the user who created the task
        user_id = task.created_for_device.user.id if task.created_for_device else None

        # Continue if user is found
        if user_id:
            task_data = {
                'id': task.id,
                'description': task.task_description,
                'priority': task.priority,
                'due_date': str(task.due_date),
                'status': task.status,
            }

            # Broadcast the task notification to the WebSocket group (based on user ID)
            async_to_sync(channel_layer.group_send)(
                f"user_notifications_{user_id}",  # Group name based on user ID
                {
                    'type': 'send_task_notification',
                    'data': task_data,
                }
            )

@shared_task
def send_harvest_notifications():
    today = datetime.now().date()
    pods = Pod.objects.filter(
        Q(harvest_start_date__lte=today) & 
        Q(harvest_end_date__gte=today)  # In harvesting range
    )
    
    for pod in pods:
        todo = Todo.objects.filter(
            created_for_pod=pod, status='pending'
        ).first()
        if todo:
            days_since_last_notification = (today - todo.created_at.date()).days
            if days_since_last_notification >= 14:  # Reminder every two weeks
                send_notification(pod.device.user, f"Reminder to harvest crops from Pod {pod.pod_number}.")
            elif days_since_last_notification >= 3:  # Notify every 3 days if not done
                send_notification(pod.device.user, f"Your crop in Pod {pod.pod_number} is ready to harvest!")



@shared_task
def update_pod_status():
    """
    Task to update the status of pods based on their fruiting and harvesting dates.
    """
    today = date.today()

    # Update status to 'Fruiting'
    pods_in_fruiting = Pod.objects.filter(
        fruiting_date__isnull=False,
        harvest_start_date__isnull=False,
        fruiting_date__lte=today,
        harvest_start_date__gt=today
    )
    # print("Pods in Fruiting Stage:")
    # for pod in pods_in_fruiting:
    #     print(f"Pod ID: {pod.id}, Crop ID: {pod.crop_id}, Fruiting Date: {pod.fruiting_date}, Harvest Start Date: {pod.harvest_start_date}")

    pods_in_fruiting.update(status="Fruiting")

    # Update status to 'Harvesting'
    pods_in_harvesting = Pod.objects.filter(
        harvest_start_date__isnull=False,
        harvest_end_date__isnull=False,
        harvest_start_date__lte=today,
        harvest_end_date__gte=today
    )
    print("Pods in Harvesting Stage:")
    for pod in pods_in_harvesting:
        print(f"Pod ID: {pod.id}, Crop ID: {pod.crop_id}, Harvest Start Date: {pod.harvest_start_date}, Harvest End Date: {pod.harvest_end_date}")

    pods_in_harvesting.update(status="Harvesting")


from django.utils.timezone import now

@shared_task
def check_pods_for_harvest():
    """
    This Celery task checks all pods in the database and creates a 'Todo' 
    task for any pod that has reached its harvest start date.
    """
    today = now().date()

    # Get all pods that have reached their harvest start date
    pods_ready_for_harvest = Pod.objects.filter(harvest_start_date__lte=today)

    for pod in pods_ready_for_harvest:
        # Check if a Todo already exists for this Pod and harvest cycle
        existing_todo = Todo.objects.filter(
            created_for_pod=pod,
            due_date=pod.harvest_end_date,
            task_description=f"Harvest {pod.crop.name} in Pod {pod.pod_number}"
        ).exists()

        if not existing_todo:
            # Create a new Todo
            Todo.objects.create(
                created_for_device=pod.device,
                created_for_pod=pod,
                due_date=pod.harvest_end_date,
                priority="high",
                task_description=f"Harvest {pod.crop.name} in Pod {pod.pod_number}"
            )

    return f"Checked {pods_ready_for_harvest.count()} pods for harvesting"

from celery import shared_task
from .models import DeviceAuditLog
from .signals import check_abnormalities

@shared_task
def check_past_logs_for_abnormalities():
    """
    Runs periodically to check existing logs for abnormalities.
    """
    logs = DeviceAuditLog.objects.all()
    for log in logs:
        check_abnormalities(DeviceAuditLog, log, created=True)
