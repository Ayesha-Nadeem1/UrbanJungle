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