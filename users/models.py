from django.contrib.auth.models import AbstractUser
from django.db import models
from datetime import timedelta

class User(AbstractUser):
    username = models.CharField(max_length=150, unique=True)  # Explicitly redefine username
    password = models.CharField(max_length=128)  # Explicitly redefine password
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)  # Add name field
    address = models.TextField(blank=True, null=True)
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    is_admin = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)  # New field


    def __str__(self):
        return self.username
    
class Address(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="addresses")
    full_name = models.CharField(max_length=255)
    address = models.TextField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)
    is_selected = models.BooleanField(default=False) 

    def __str__(self):
        return f"{self.full_name}, {self.address}, {self.city}"



# Device Model
class Device(models.Model):
    din = models.CharField(max_length=50, unique=True)  # User-provided DIN
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="devices")
    qr_code = models.ImageField(upload_to="qr_codes/", blank=True, null=True)
    device_type = models.CharField(max_length=255, default="Urban Jungle")
    device_name = models.CharField(max_length=255, null=False)

    def clean(self):
        # Ensure device_name is unique for the specific user (owner)
        if self.device_name:
            if Device.objects.filter(owner=self.owner, device_name=self.device_name).exclude(pk=self.pk).exists():
                raise ValidationError(f"The device name '{self.device_name}' is already present.")

    def save(self, *args, **kwargs):
        # Call the clean method before saving
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Device {self.din}"


# Crop Model
class Crop(models.Model):
    name = models.CharField(max_length=255, unique= True)
    life_cycle = models.PositiveIntegerField(help_text="Life cycle in days")
    min_optimal_temperature = models.FloatField(help_text="Optimal temperature in °C",default=15)
    min_optimal_humidity = models.FloatField(help_text="Optimal humidity in %",default=30)
    min_optimal_tds = models.TextField(help_text="Nutrients needed",default=600)
    min_optimal_water_temperature = models.TextField(help_text="water temperature needed",default=15)
    max_optimal_temperature = models.FloatField(help_text="Optimal temperature in °C",default=25)
    max_optimal_humidity = models.FloatField(help_text="Optimal humidity in %",default=70)
    max_optimal_tds = models.TextField(help_text="Nutrients needed",default=1000)
    max_optimal_water_temperature = models.TextField(help_text="water temperature needed",default=30)
    #water = models.FloatField(help_text="Water needed in liters")
    required_light_duration = models.PositiveIntegerField(blank=True,null=True)
    seeding_days = models.PositiveIntegerField(blank=True,null=True)
    sampling_days = models.PositiveIntegerField(blank=True,null=True)
    growth_days = models.PositiveIntegerField(blank=True,null=True)
    fruiting_days = models.PositiveIntegerField(blank=True,null=True)
    harvesting_days = models.PositiveIntegerField(blank=True,null=True)

    def __str__(self):
        return self.name

from rest_framework.exceptions import ValidationError
# Pod Model
class Pod(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="pods")
    crop = models.ForeignKey(Crop, on_delete=models.CASCADE, related_name="pods")
    pod_number = models.PositiveIntegerField(help_text="Pod number of the device", null=True, blank=True)
    custom_name = models.TextField(help_text="Custom name for the crop")
    planting_date = models.DateField(blank=True, null=True)  # When the crop was planted
    fruiting_date = models.DateField(blank=True, null=True)  # Calculated based on crop
    harvest_start_date = models.DateField(blank=True, null=True)  # When harvesting starts
    harvest_end_date = models.DateField(blank=True, null=True)  # When harvesting ends
    status = models.CharField(max_length=255, default="Seedling")

    def clean(self):
        """
        Custom validation logic to check for uniqueness of device and pod_number.
        """
        if Pod.objects.filter(device=self.device, pod_number=self.pod_number).exclude(pk=self.pk).exists():
            existing_pod = Pod.objects.get(device=self.device, pod_number=self.pod_number)
            raise ValidationError(f"{existing_pod.crop.name} is already planted in pod number {self.pod_number}.")

    def save(self, *args, **kwargs):
        """
        Automatically calculate and set harvest_start_date, harvest_end_date, and fruiting_date
        based on planting_date and crop lifecycle.
        """
        if self.planting_date and self.crop:
            # Calculate harvest start date (Lifecycle - Harvesting Days)
            harvest_start_offset = self.crop.life_cycle - self.crop.harvesting_days
            self.harvest_start_date = self.planting_date + timedelta(days=harvest_start_offset)

            # Calculate harvest end date (Harvest Start Date + Harvesting Days)
            self.harvest_end_date = self.harvest_start_date + timedelta(days=self.crop.harvesting_days)

            # Calculate fruiting date if the crop has fruiting days
            if self.crop.fruiting_days:
                self.fruiting_date = self.planting_date + timedelta(days=self.crop.fruiting_days)
            else:
                self.fruiting_date = None

        # Perform the custom validation before saving
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Pod {self.pod_number} in {self.device.din} holding {self.crop.name}"
            
# Light Scheduling Model
class LightSchedule(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="light_schedule")
    handled_by_user = models.BooleanField(default=False)
    schedule_for_week = models.JSONField(blank=True, null=True)
    light_on_time = models.TimeField(blank=True, null=True)
    light_on_duration = models.DurationField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.handled_by_user: #manual scheduling
            # Ensure both `light_on_time` and `light_on_duration` are provided
            if self.light_on_time is not None or self.light_on_duration is not None:
                raise ValueError(
                    "In manual scheduling, both time to turn the light and duration must be null. It should be provided in week's schedule."
                )
        else: #scheduling by team
            # Set `light_on_duration` to None
            #self.light_on_duration = None
            if self.light_on_time is None:
                raise ValueError(
                    "Time to turn the light on must be provided."
                )

        # Call the parent save method
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Light schedule for {self.device.din}"



# Audit Logs Model
class DeviceAuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    temperature = models.FloatField(help_text="current temperature",null=True)
    humidity = models.FloatField(help_text="current humidity",null=True)
    tds = models.TextField(help_text="current tds",null=True)
    water_temperature = models.TextField(help_text="current water temperature",null=True)
    error_codes = models.TextField(help_text="Custom name for the crop",null=True)
    
    def __str__(self):
        return f"Log at {self.timestamp} - {self.action}"

class Todo(models.Model):
    PRIORITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low')
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('done', 'Done'),
        ('expired', 'Expired'),
        ('urgent', 'Urgent'),
    ]
    
    id = models.AutoField(primary_key=True)
    #created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_for_device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="device",null=True)
    created_for_pod = models.ForeignKey(Pod, on_delete=models.CASCADE, related_name="pod",null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    due_date = models.DateField()  # Date for which the to-do is created
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    task_description = models.TextField()

    def __str__(self):
        return f"{self.task_description} ({self.priority})"

#ecom models:
from django.db import models

class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

class Product(models.Model):
    name = models.CharField(max_length=255)  # Required
    product_type = models.CharField(max_length=255)  # Required
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')  # Required
    description = models.TextField(blank=True, null=True)  # Optional
    price = models.DecimalField(max_digits=10, decimal_places=2)  # Required (Dollars)
    picture = models.URLField(max_length=500)  # Required (Image URL)
    stock = models.IntegerField(default=0)  # Required
    delivery_charges = models.DecimalField(max_digits=10, decimal_places=2)  # Required
    discounted_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)  # Optional
    is_discounted = models.BooleanField(default=False)  # Required (Flag for discount)

    def __str__(self):
        return self.name
    
class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    is_selected = models.BooleanField(default=False)

class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, choices=[
        ('pending', 'Pending'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('canceled', 'Canceled')
    ], default='pending')

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

class Blog(models.Model):
    title = models.CharField(max_length=255)
    image = models.ImageField(upload_to='blog_images/', blank=True, null=True)
    body = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blogs')
    category = models.CharField(max_length=100)
    date_published = models.DateTimeField(auto_now_add=True)
    reading_time = models.PositiveIntegerField(help_text="Estimated reading time in minutes")

    def __str__(self):
        return self.title