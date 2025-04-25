from rest_framework import serializers
from .models import User, Crop, Device,Pod
from django.contrib.auth.hashers import make_password, check_password

from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    profile_picture = serializers.ImageField(required=False, allow_null=True)  # New field

    class Meta:
        model = User
        fields = [
            'id', 'username', 'password', 'email', 'name','address', 
             'contact_number', 'is_admin', 'profile_picture'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)
        instance.save()
        return instance

    
class CropSerializer(serializers.ModelSerializer):
    class Meta:
        model = Crop
        fields = [
            'id',
            'name',
            'life_cycle',
            'min_optimal_temperature',
            'max_optimal_temperature',
            'min_optimal_humidity',
            'max_optimal_humidity',
            'min_optimal_tds',
            'max_optimal_tds',
            'required_light_duration',
            'seeding_days',
            'sampling_days',
            'growth_days',
            'fruiting_days',
            'harvesting_days',
        ]
        read_only_fields = ['life_cycle']

    def create(self, validated_data):
        # Calculate life cycle dynamically
        validated_data['life_cycle'] = sum(filter(None, [
            validated_data.get('seeding_days', 0),
            validated_data.get('sampling_days', 0) ,
            validated_data.get('growth_days', 0) ,
            validated_data.get('fruiting_days', 0) ,
            validated_data.get('harvesting_days', 0) 
        ]))
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Recalculate life cycle dynamically
        instance.life_cycle = sum(filter(None, [
            validated_data.get('seeding_days', instance.seedling_days) or 0,
            validated_data.get('sampling_days', instance.sampling_days or 0) ,
            validated_data.get('growth_days', instance.growth_days or 0) ,
            validated_data.get('fruiting_days', instance.fruiting_days or 0) ,
            validated_data.get('harvesting_days', instance.harvesting_days or 0) 
        ]))
        return super().update(instance, validated_data)

class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'din', 'qr_code', 'device_type','device_name']  # Exclude 'owner'
        read_only_fields = ['id', 'qr_code']


class PodSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pod
        fields = [
            'id',
            'device',
            'crop',
            'pod_number',
            'custom_name',
            'planting_date',
            'fruiting_date',
            'harvest_start_date',
            'harvest_end_date',
        ]
        read_only_fields = ['fruiting_date', 'harvest_start_date', 'harvest_end_date']

    def validate(self, data):
        device = data.get('device')
        pod_number = data.get('pod_number')

        # Check if a pod with the same device and pod_number already exists
        existing_pod = Pod.objects.filter(device=device, pod_number=pod_number).first()
        if existing_pod:
            raise serializers.ValidationError(
                f"{existing_pod.crop.name} is already planted in pod number {pod_number}."
            )

        return data

    
from .models import Todo

class TodoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Todo
        fields = '__all__'

from .models import DeviceAuditLog

class DeviceAuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceAuditLog
        fields = '__all__'

from rest_framework import serializers
from .models import Category, Product, Cart, CartItem, Order, OrderItem, Address

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'

    def validate(self, data):
        """Ensure consistency of discount fields"""
        if data.get('is_discounted') and not data.get('discounted_price'):
            raise serializers.ValidationError("Discounted price is required when is_discounted is true.")
        return data

class CartItemSerializer(serializers.ModelSerializer):
    is_selected = serializers.BooleanField(required=False)  # Make it writable

    class Meta:
        model = CartItem
        fields = '__all__'


class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)

    class Meta:
        model = Cart
        fields = '__all__'

class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = '__all__'

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = '__all__'

class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'
        read_only_fields = ['user']  

from .models import Blog

class BlogSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source='author.username')

    class Meta:
        model = Blog
        fields = '__all__'

from .models import LightSchedule, Device, Crop

class LightScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = LightSchedule
        fields = '__all__'
        read_only_fields = ('device',)

    def validate(self, data):
        handled_by_user = data.get('handled_by_user', False)
        
        if handled_by_user:
            # Manual scheduling validation
            schedule_for_week = data.get('schedule_for_week')
            if not schedule_for_week:
                raise serializers.ValidationError("Weekly schedule is required for manual scheduling")
            
            # Validate the schedule_for_week structure
            self._validate_weekly_schedule(schedule_for_week)
            
            if data.get('light_on_time') or data.get('light_on_duration'):
                raise serializers.ValidationError("light_on_time and light_on_duration must be null for manual scheduling")
        else:
            # Automatic scheduling validation
            if data.get('schedule_for_week'):
                raise serializers.ValidationError("Weekly schedule must be null for automatic scheduling")
            if not data.get('light_on_time'):
                raise serializers.ValidationError("light_on_time is required for automatic scheduling")
            
            if not data.get('light_on_duration'):
                first_crop = Crop.objects.first()
                if first_crop and first_crop.required_light_duration:
                    data['light_on_duration'] = first_crop.required_light_duration
                else:
                    raise serializers.ValidationError("No crop with light duration found")
        
        return data

    def _validate_weekly_schedule(self, schedule):
        """Validate the structure of the weekly schedule"""
        weekdays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
        
        # Check all weekdays are present
        missing_days = [day for day in weekdays if day not in schedule]
        if missing_days:
            raise serializers.ValidationError(f"Missing schedule for days: {', '.join(missing_days)}")
        
        # Validate each day's schedule
        for day, day_schedule in schedule.items():
            if day.lower() not in weekdays:
                raise serializers.ValidationError(f"Invalid day '{day}' in schedule")
            
            # Support both simple hours (int) or detailed schedule (dict)
            if isinstance(day_schedule, dict):
                if 'on_time' not in day_schedule or 'duration' not in day_schedule:
                    raise serializers.ValidationError(f"Day '{day}' schedule must contain 'on_time' and 'duration'")
            elif not isinstance(day_schedule, (int, float)):
                raise serializers.ValidationError(f"Day '{day}' schedule must be either hours (number) or detailed schedule (dict)")

    def validate_device(self, value):
        if self.context['request'].user != value.owner:
            raise serializers.ValidationError("You don't own this device")
        return value