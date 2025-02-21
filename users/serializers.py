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
            'id', 'username', 'password', 'email', 'name', 
            'address', 'contact_number', 'is_admin', 'profile_picture'
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
# class PodSerializer(serializers.ModelSerializer):
#     crop_name = serializers.ReadOnlyField(source='crop.name')  # Include crop name for easy display

#     class Meta:
#         model = Pod
#         fields = ['id', 'device', 'crop', 'crop_name', 'custom_name']

#     def create(self, validated_data):
#         """Create a new pod"""
#         device = validated_data.get('device')
#         crop = validated_data.get('crop')
#         custom_name = validated_data.get('custom_name')

#         # Check for existing pods with the same crop and group them
#         existing_pod = Pod.objects.filter(device=device, crop=crop).first()
#         if existing_pod:
#             # Update the custom_name JSON for existing pod
#             if not existing_pod.custom_name:
#                 existing_pod.custom_name = {}
#             existing_pod.custom_name.update(custom_name)
#             existing_pod.save()
#             return existing_pod
#         else:
#             return Pod.objects.create(**validated_data)


# class PodSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Pod
#         fields = ['id', 'device', 'crop', 'custom_name', 'planting_date', 'harvest_date']
#         read_only_fields = ['harvest_date']

#     def validate(self, data):
#         device = data.get('device')
#         crop = data.get('crop')
#         custom_name = data.get('custom_name')

#         # Get all existing pods for this device
#         existing_pods = Pod.objects.filter(device=device)

#         # Check for conflicting crops
#         conflicting_pods = existing_pods.exclude(crop=crop)
#         if conflicting_pods.exists():
#             for pod_name in custom_name.keys():
#                 for pod in conflicting_pods:
#                     if pod_name in pod.custom_name:
#                         raise serializers.ValidationError(
#                             f"Pod '{pod_name}' in this device is already planted with another crop ({pod.crop.name})."
#                         )

#         # Check if the provided pod names are already occupied with another crop
#         for pod_name in custom_name.keys():
#             for pod in existing_pods:
#                 if pod_name in pod.custom_name and pod.crop != crop:
#                     raise serializers.ValidationError(
#                         f"Pod '{pod_name}' is already occupied by another crop ({pod.crop.name})."
#                     )

#         return data

#     def create(self, validated_data):
#         device = validated_data.get('device')
#         crop = validated_data.get('crop')
#         custom_name = validated_data.get('custom_name')
#         planting_date = validated_data.get('planting_date')

#         # Check if there's already an entry for the same device and crop
#         existing_pod = Pod.objects.filter(device=device, crop=crop).first()
#         if existing_pod:
#             # Combine custom names
#             existing_custom_name = existing_pod.custom_name or {}
#             existing_custom_name.update(custom_name)
#             existing_pod.custom_name = existing_custom_name
#             existing_pod.save()
#             return existing_pod

#         # Calculate harvest_date based on planting_date and crop life cycle
#         if planting_date:
#             validated_data['harvest_date'] = planting_date + timedelta(days=crop.life_cycle)

#         # Create a new record if no existing entry is found
#         return super().create(validated_data)

#     def update(self, instance, validated_data):
#         custom_name = validated_data.get('custom_name', instance.custom_name)
#         planting_date = validated_data.get('planting_date', instance.planting_date)

#         # Update custom names by merging the new ones with existing ones
#         instance.custom_name.update(custom_name)

#         # Update planting_date and recalculate harvest_date
#         if planting_date:
#             instance.planting_date = planting_date
#             instance.harvest_date = planting_date + timedelta(days=instance.crop.life_cycle)

#         instance.save()
#         return instance

from .models import DeviceAuditLog

class DeviceAuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceAuditLog
        fields = '__all__'
