from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from .models import User,Crop,Device,Todo,Pod
from .serializers import UserSerializer,CropSerializer,DeviceSerializer,TodoSerializer,PodSerializer
from .permissions import IsAdminUser
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
import jwt
from django.conf import settings

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class SignupView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        if not check_password(password, user.password):
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        tokens = get_tokens_for_user(user)
        return Response({'tokens': tokens}, status=status.HTTP_200_OK)
    
from django.contrib.auth import get_user_model
User = get_user_model()

class GetUserDataView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        token = request.headers.get('Authorization', '').split(' ')[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)


class UpdateUserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        token = request.headers.get('Authorization', '').split(' ')[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            authenticated_user_id = payload['user_id']

            # Ensure the user exists
            user = User.objects.get(id=authenticated_user_id)

            # Check if the user is trying to update their own data
            if 'id' in request.data and str(request.data['id']) != str(authenticated_user_id):
                return Response({'error': 'You are not allowed to update this user.'}, status=status.HTTP_403_FORBIDDEN)

            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)
        
class AdminSignupView(APIView):
    def post(self, request):
        data = request.data
        data['is_admin'] = True  # Automatically set is_admin to True for admin users

        # Create the admin user with the modified data
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Admin user registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_admin:
            return Response({'error': 'Not an admin user'}, status=status.HTTP_403_FORBIDDEN)

        if not check_password(password, user.password):
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        tokens = get_tokens_for_user(user)
        return Response({'tokens': tokens}, status=status.HTTP_200_OK)


from rest_framework_simplejwt.tokens import RefreshToken
from .utils import generate_access_token, decode_token

class TokenRefreshView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        if not refresh_token:
            return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        decoded_data = decode_token(refresh_token)
        if not decoded_data:
            return Response({"error": "Invalid or expired refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        user_id = decoded_data.get("user_id")
        access_token = generate_access_token(user_id)

        return Response({"access_token": access_token}, status=status.HTTP_200_OK)



from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAdminUser

class CropListCreateView(APIView):
    def get(self, request, *args, **kwargs):
        """Retrieve all crops"""
        crops = Crop.objects.all()
        serializer = CropSerializer(crops, many=True)
        return Response(serializer.data)

    @permission_classes([IsAdminUser])
    def post(self, request, *args, **kwargs):
        """Create new crops"""
        crops_data = request.data  # Directly expecting a list of crops
        if isinstance(crops_data, list):  # Check if data is a list
            serializer = CropSerializer(data=crops_data, many=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": "Invalid data format. Expected a list."}, status=status.HTTP_400_BAD_REQUEST)


class CropRetrieveUpdateDeleteView(APIView):
    permission_classes = [IsAdminUser]

    def get_object(self, crop_id):
        try:
            return Crop.objects.get(id=crop_id)
        except Crop.DoesNotExist:
            return None

    def get(self, request, crop_id, *args, **kwargs):
        """Retrieve a crop by ID"""
        crop = self.get_object(crop_id)
        if not crop:
            return Response({"error": "Crop not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CropSerializer(crop)
        return Response(serializer.data)

    def put(self, request, crop_id, *args, **kwargs):
        """Update a crop"""
        crop = self.get_object(crop_id)
        if not crop:
            return Response({"error": "Crop not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CropSerializer(crop, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, crop_id, *args, **kwargs):
        """Delete a crop"""
        crop = self.get_object(crop_id)
        if not crop:
            return Response({"error": "Crop not found"}, status=status.HTTP_404_NOT_FOUND)
        crop.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CropNamesView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    def get(self, request):
        # Query to get all crop names
        crop_names = Crop.objects.values_list('name', flat=True)
        return Response({"crop_names": list(crop_names)}, status=200)
    
# class DeviceCreateRetrieveView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         """Create a new device"""
#         # The owner of the device is automatically set as the authenticated user
#         serializer = DeviceSerializer(data=request.data, context={'request': request})
#         if serializer.is_valid():
#             device = serializer.save(owner=request.user)
#             return Response(DeviceSerializer(device).data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def get(self, request, *args, **kwargs):
#         """Retrieve a list of devices for the authenticated user"""
#         # Retrieve only devices belonging to the authenticated user (owner)
#         devices = Device.objects.filter(owner=request.user)
#         serializer = DeviceSerializer(devices, many=True)
#         return Response(serializer.data)
    
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

class DeviceCreateRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Create a new device and send a WebSocket notification."""
        # Check if DIN is valid
        din = request.data.get('din')
        if not ValidDIN.objects.filter(din=din).exists():
            return Response(
                {"error": "Invalid DIN. Please provide a valid device identification number."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = DeviceSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            device = serializer.save(owner=request.user)

            # Send WebSocket notification
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"user_device_notifications_{request.user.id}",  # Group name for user
                {
                    "type": "send_device_notification",  # Calls method in WebSocket consumer
                    "data": {
                        "message": f"New device '{device.device_name}' has been added!",
                        "device_id": device.id,
                        "status": "success",
                    },
                },
            )

            return Response(DeviceSerializer(device).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeviceUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, device_id):
        try:
            # Get the device by ID and ensure it belongs to the authenticated user
            device = Device.objects.get(id=device_id)
            if device.owner != self.request.user:
                raise PermissionDenied("You do not have permission to access this device.")
            return device
        except Device.DoesNotExist:
            raise PermissionDenied("Device not found.")

    def put(self, request, device_id, *args, **kwargs):
        """Update an existing device"""
        device = self.get_object(device_id)
        serializer = DeviceSerializer(device, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, device_id, *args, **kwargs):
        """Delete an existing device"""
        device = self.get_object(device_id)
        device.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .models import ValidDIN
from .permissions import IsAdminUser

class ValidDINListCreateView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """List all valid DINs (Admin only)"""
        dins = ValidDIN.objects.all().order_by('-created_at')
        data = [{"din": din.din, "created_at": din.created_at} for din in dins]
        return Response(data)

    def post(self, request):
        """Create a new valid DIN (Admin only)"""
        din = request.data.get('din')
        if not din:
            return Response({"error": "DIN is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            valid_din = ValidDIN.objects.create(din=din)
            return Response({"din": valid_din.din}, status=status.HTTP_201_CREATED)
        except IntegrityError:
            return Response({"error": "DIN already exists"}, status=status.HTTP_400_BAD_REQUEST)

class ValidDINRetrieveUpdateDestroyView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_object(self, pk):
        try:
            return ValidDIN.objects.get(pk=pk)
        except ValidDIN.DoesNotExist:
            return None

    def get(self, request, pk):
        """Retrieve a specific DIN by ID (Admin only)"""
        valid_din = self.get_object(pk)
        if not valid_din:
            return Response({"error": "DIN not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({
            "id": valid_din.id,
            "din": valid_din.din, 
            "created_at": valid_din.created_at
        })

    def put(self, request, pk):
        """Update a DIN (Admin only)"""
        valid_din = self.get_object(pk)
        if not valid_din:
            return Response({"error": "DIN not found"}, status=status.HTTP_404_NOT_FOUND)
        
        din_value = request.data.get('din')
        if not din_value:
            return Response({"error": "DIN is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if new DIN already exists (excluding current record)
        if ValidDIN.objects.filter(din=din_value).exclude(pk=valid_din.pk).exists():
            return Response({"error": "This DIN already exists"}, status=status.HTTP_400_BAD_REQUEST)
        
        valid_din.din = din_value
        valid_din.save()
        return Response({
            "id": valid_din.id,
            "din": valid_din.din,
            "created_at": valid_din.created_at
        })

    def delete(self, request, pk):
        """Delete a DIN by ID (Admin only)"""
        valid_din = self.get_object(pk)
        if not valid_din:
            return Response({"error": "DIN not found"}, status=status.HTTP_404_NOT_FOUND)
        valid_din.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class PodCreateRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    # def post(self, request, *args, **kwargs):
    #     """Create a new pod"""
    #     din = request.data.get('din')  # Get the device DIN from the request
    #     if not din:
    #         return Response({"error": "DIN is required."}, status=status.HTTP_400_BAD_REQUEST)

    #     try:
    #         # Fetch the device and ensure the user is the owner
    #         device = Device.objects.get(din=din)
    #         if device.owner != request.user:
    #             return Response({"error": "You do not own this device."}, status=status.HTTP_403_FORBIDDEN)

    #         # Add the device to the request data
    #         request.data['device'] = device.id

    #         serializer = PodSerializer(data=request.data)
    #         if serializer.is_valid():
    #             pod = serializer.save()
    #             return Response(PodSerializer(pod).data, status=status.HTTP_201_CREATED)
    #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    #     except Device.DoesNotExist:
    #         return Response({"error": "Invalid DIN."}, status=status.HTTP_404_NOT_FOUND)
    def post(self, request, *args, **kwargs):
        """Create a new pod"""
        din = request.data.get('din')
        if not din:
            return Response({"error": "DIN is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            device = Device.objects.get(din=din)
            if device.owner != request.user:
                return Response({"error": "You do not own this device."}, status=status.HTTP_403_FORBIDDEN)

            request.data['device'] = device.id
            serializer = PodSerializer(data=request.data)
            
            if serializer.is_valid():
                pod = serializer.save()
                
                # Create audit log entry
                PodAuditLog.objects.create(
                    pod=pod,
                    device=device,
                    owner=request.user,
                    crop=pod.crop,
                    crop_name=pod.crop.name,
                    planting_date=pod.planting_date,
                    action='CREATE'
                )
                
                return Response(PodSerializer(pod).data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Device.DoesNotExist:
            return Response({"error": "Invalid DIN."}, status=status.HTTP_404_NOT_FOUND)

    def get(self, request, *args, **kwargs):
        """Retrieve pods for a specific device owned by the authenticated user"""
        din = request.data.get('din')  # Use query params to fetch DIN
        if not din:
            return Response({"error": "DIN is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the device and ensure the user is the owner
            device = Device.objects.get(din=din)
            if device.owner != request.user:
                return Response({"error": "You do not own this device."}, status=status.HTTP_403_FORBIDDEN)

            # Retrieve all pods for the device
            pods = Pod.objects.filter(device=device)
            serializer = PodSerializer(pods, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Device.DoesNotExist:
            return Response({"error": "Invalid DIN."}, status=status.HTTP_404_NOT_FOUND)

from .models import PodAuditLog
class PodUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def get_device(self, device_id, user):
        """Fetch the device and ensure ownership"""
        try:
            device = Device.objects.get(id=device_id)
            if device.owner != user:
                raise PermissionDenied("You do not own this device.")
            return device
        except Device.DoesNotExist:
            raise PermissionDenied("Device not found.")

    # def put(self, request, device_id, *args, **kwargs):
    #     """Update a specific pod of a device"""
    #     device = self.get_device(device_id, request.user)
    #     pod_id = request.data.get('pod_id')

    #     if not pod_id:
    #         return Response({"error": "Pod ID is required for update."}, status=status.HTTP_400_BAD_REQUEST)

    #     try:
    #         pod = Pod.objects.get(id=pod_id, device=device)
    #         serializer = PodSerializer(pod, data=request.data, partial=True)
    #         if serializer.is_valid():
    #             pod = serializer.save()
    #             return Response(PodSerializer(pod).data, status=status.HTTP_200_OK)
    #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    #     except Pod.DoesNotExist:
    #         return Response({"error": "Pod not found in this device."}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, device_id, *args, **kwargs):
        """Update a specific pod of a device"""
        device = self.get_device(device_id, request.user)
        pod_id = request.data.get('pod_id')

        if not pod_id:
            return Response({"error": "Pod ID is required for update."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            pod = Pod.objects.get(id=pod_id, device=device)
            old_crop = pod.crop
            old_planting_date = pod.planting_date
            
            serializer = PodSerializer(pod, data=request.data, partial=True)
            if serializer.is_valid():
                pod = serializer.save()
                
                # Check if crop or planting date changed
                if pod.crop != old_crop or pod.planting_date != old_planting_date:
                    PodAuditLog.objects.create(
                        pod=pod,
                        device=device,
                        owner=request.user,
                        crop=pod.crop,
                        crop_name=pod.crop.name,
                        planting_date=pod.planting_date,
                        action='UPDATE'
                    )
                
                return Response(PodSerializer(pod).data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Pod.DoesNotExist:
            return Response({"error": "Pod not found in this device."}, status=status.HTTP_404_NOT_FOUND)


    def delete(self, request, device_id, *args, **kwargs):
        """Delete a specific pod of a device"""
        device = self.get_device(device_id, request.user)
        pod_id = request.data.get('pod_id')

        if not pod_id:
            return Response({"error": "Pod ID is required for deletion."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            pod = Pod.objects.get(id=pod_id, device=device)
            pod.delete()
            return Response({"message": f"Pod {pod_id} deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Pod.DoesNotExist:
            return Response({"error": "Pod not found in this device."}, status=status.HTTP_404_NOT_FOUND)

class PodAuditLogView(APIView):
    permission_classes = [IsAuthenticated]

    def get_pod(self, pod_id, user):
        """Helper method to get pod and verify ownership"""
        try:
            pod = Pod.objects.get(id=pod_id)
            if pod.device.owner != user:
                raise PermissionDenied("You don't have permission to view this pod's audit logs.")
            return pod
        except Pod.DoesNotExist:
            raise NotFound("Pod not found.")

    def get_device(self, device_id, user):
        """Helper method to get device and verify ownership"""
        try:
            device = Device.objects.get(id=device_id)
            if device.owner != user:
                raise PermissionDenied("You don't have permission to view this device's audit logs.")
            return device
        except Device.DoesNotExist:
            raise NotFound("Device not found.")

class SinglePodAuditLogView(PodAuditLogView):
    """Get audit logs for a specific pod"""
    def get(self, request, pod_id):
        pod = self.get_pod(pod_id, request.user)
        logs = PodAuditLog.objects.filter(pod=pod).order_by('-log_date')
        
        data = [{
            'id': log.id,
            'pod_id': log.pod.id,
            'device_id': log.device.id,
            'device_din': log.device.din,
            'crop_id': log.crop.id,
            'crop_name': log.crop_name,
            'planting_date': log.planting_date,
            'log_date': log.log_date,
            'action': log.action
        } for log in logs]
        
        return Response(data)

class DevicePodsAuditLogView(PodAuditLogView):
    """Get audit logs for all pods of a specific device"""
    def get(self, request, device_id):
        device = self.get_device(device_id, request.user)
        logs = PodAuditLog.objects.filter(device=device).order_by('-log_date')
        
        data = [{
            'id': log.id,
            'pod_id': log.pod.id,
            'pod_number': log.pod.pod_number,
            'crop_id': log.crop.id,
            'crop_name': log.crop_name,
            'planting_date': log.planting_date,
            'log_date': log.log_date,
            'action': log.action
        } for log in logs]
        
        return Response(data)

class UserDevicesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Get all devices of the authenticated user.
        """
        devices = Device.objects.filter(owner=request.user)
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DeviceDetailByNameView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Get complete data of a specific device by its name.
        Only the owner of the device can access its details.
        The device name is provided in the request body.
        """
        device_name = request.data.get("device_name")  # Extract device name from request body
        if not device_name:
            return Response(
                {"error": "Device name is required in the request body."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Find the device by name and check ownership
        device = get_object_or_404(Device, device_name=device_name)
        if device.owner != request.user:
            raise PermissionDenied("You do not have permission to access this device.")

        # Serialize the device details
        serializer = DeviceSerializer(device)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TodoListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Retrieve a list of all todos created by the authenticated user.
        """
        todos = Todo.objects.filter(created_by=request.user)
        serializer = TodoSerializer(todos, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Create a new todo. The `created_by` field is automatically set to the authenticated user.
        """
        data = request.data
        serializer = TodoSerializer(data=data)
        if serializer.is_valid():
            serializer.save(created_by=request.user)  # Automatically set the user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TodoRetrieveUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated,IsAdminUser]

    def get_object(self, pk, user):
        """
        Get the todo object by its primary key and ensure it belongs to the requesting user.
        """
        todo = get_object_or_404(Todo, pk=pk, created_by=user)
        return todo

    def get(self, request, pk, *args, **kwargs):
        """
        Retrieve the details of a specific todo by its ID.
        """
        todo = self.get_object(pk, request.user)
        serializer = TodoSerializer(todo)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, *args, **kwargs):
        """
        Update the details of an existing todo. The `created_by` field cannot be modified.
        """
        todo = self.get_object(pk, request.user)
        serializer = TodoSerializer(todo, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()  # Save the updated data
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, *args, **kwargs):
        """
        Delete a specific todo by its ID.
        """
        todo = self.get_object(pk, request.user)
        todo.delete()
        return Response({"detail": "Todo deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    

class UserTodoListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        todos = Todo.objects.filter(created_for_device__owner=user)
        serializer = TodoSerializer(todos, many=True)
        return Response(serializer.data)
    
class MarkTodoDoneView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            todo = Todo.objects.get(pk=pk, created_for_device__owner=request.user)
            todo.status = 'done'
            todo.save()
            return Response({"message": "Todo marked as done."}, status=status.HTTP_200_OK)
        except Todo.DoesNotExist:
            return Response({"error": "Todo not found."}, status=status.HTTP_404_NOT_FOUND)
        
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .utils import parse_and_save_device_data

class ReceiveDeviceData(APIView):
    """
    API view to receive and process IoT device data.
    """

    def post(self, request, *args, **kwargs):
        data_string = request.data.get("data_string")
        if not data_string:
            return Response({"error": "No data provided"}, status=status.HTTP_400_BAD_REQUEST)

        audit_log = parse_and_save_device_data(data_string)

        if audit_log:
            return Response({"message": "Data processed successfully"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "Failed to process data"}, status=status.HTTP_400_BAD_REQUEST)


# class PodCreateRetrieveView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         """Create a new pod"""
#         din = request.data.get('din')  # Get the device DIN from the request
#         if not din:
#             return Response({"error": "DIN is required."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Fetch the device and ensure the user is the owner
#             device = Device.objects.get(din=din)
#             if device.owner != request.user:
#                 return Response({"error": "You do not own this device."}, status=status.HTTP_403_FORBIDDEN)

#             # Add the device to the request data
#             request.data['device'] = device.id

#             serializer = PodSerializer(data=request.data)
#             if serializer.is_valid():
#                 serializer.save()
#                 return Response(serializer.data, status=status.HTTP_201_CREATED)
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#         except Device.DoesNotExist:
#             return Response({"error": "Invalid DIN."}, status=status.HTTP_404_NOT_FOUND)

#     def get(self, request, *args, **kwargs):
#         """Retrieve pods for a specific device owned by the authenticated user"""
#         din = request.data.get('din')  # Get the device DIN from query params
#         if not din:
#             return Response({"error": "DIN is required."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Fetch the device and ensure the user is the owner
#             device = Device.objects.get(din=din)
#             if device.owner != request.user:
#                 return Response({"error": "You do not own this device."}, status=status.HTTP_403_FORBIDDEN)

#             # Retrieve all pods for the device
#             pods = Pod.objects.filter(device=device)
#             serializer = PodSerializer(pods, many=True)
#             return Response(serializer.data, status=status.HTTP_200_OK)
#         except Device.DoesNotExist:
#             return Response({"error": "Invalid DIN."}, status=status.HTTP_404_NOT_FOUND)


# class PodUpdateDeleteView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get_device(self, device_id, user):
#         """Fetch the device and ensure ownership"""
#         try:
#             device = Device.objects.get(id=device_id)
#             if device.owner != user:
#                 raise PermissionDenied("You do not own this device.")
#             return device
#         except Device.DoesNotExist:
#             raise PermissionDenied("Device not found.")

#     def put(self, request, device_id, *args, **kwargs):
#         """Update specific pods of a device"""
#         device = self.get_device(device_id, request.user)
#         pod_id = request.data.get('pod_id')

#         if not pod_id:
#             return Response({"error": "Pod ID is required for update."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             pod = Pod.objects.get(id=pod_id, device=device)
#             serializer = PodSerializer(pod, data=request.data, partial=True)
#             if serializer.is_valid():
#                 serializer.save()
#                 return Response(serializer.data, status=status.HTTP_200_OK)
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#         except Pod.DoesNotExist:
#             return Response({"error": "Pod not found in this device."}, status=status.HTTP_404_NOT_FOUND)

#     def delete(self, request, device_id, *args, **kwargs):
#         """Delete a specific pod of a device"""
#         device = self.get_device(device_id, request.user)
#         pod_id = request.data.get('pod_id')

#         if not pod_id:
#             return Response({"error": "Pod ID is required for deletion."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             pod = Pod.objects.get(id=pod_id, device=device)
#             pod.delete()
#             return Response({"message": f"Pod {pod_id} deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
#         except Pod.DoesNotExist:
#             return Response({"error": "Pod not found in this device."}, status=status.HTTP_404_NOT_FOUND)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from .models import Category, Product, Cart, CartItem, Order, OrderItem, Address
from .serializers import (
    CategorySerializer, ProductSerializer, CartSerializer, 
    CartItemSerializer, OrderSerializer, OrderItemSerializer, AddressSerializer
)

# ---------------- CATEGORY VIEWS ----------------
class CategoryListCreateView(APIView):
    def get(self, request):
        """Retrieve all categories"""
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data)

    def post(self, request):
        """Create a new category"""
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CategoryRetrieveUpdateDeleteView(APIView):
    def get_object(self, category_id):
        try:
            return Category.objects.get(id=category_id)
        except Category.DoesNotExist:
            return None

    def get(self, request, category_id):
        """Retrieve a category by ID"""
        category = self.get_object(category_id)
        if not category:
            return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CategorySerializer(category)
        return Response(serializer.data)

    def put(self, request, category_id):
        """Update a category"""
        category = self.get_object(category_id)
        if not category:
            return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CategorySerializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, category_id):
        """Delete a category"""
        category = self.get_object(category_id)
        if not category:
            return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        category.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------- PRODUCT VIEWS ----------------
class ProductListCreateView(APIView):
    def get(self, request):
        """Retrieve all products"""
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Create a new product"""
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductRetrieveUpdateDeleteView(APIView):
    def get_object(self, product_id):
        try:
            return Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return None

    def get(self, request, product_id):
        """Retrieve a product by ID"""
        product = self.get_object(product_id)
        if not product:
            return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, product_id):
        """Update a product"""
        product = self.get_object(product_id)
        if not product:
            return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, product_id):
        """Delete a product"""
        product = self.get_object(product_id)
        if not product:
            return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        product.delete()
        return Response({"message": "Product deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
# ---------------- CART VIEWS ----------------
class CartListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve cart for logged-in user"""
        cart = Cart.objects.filter(user=request.user).first()
        if not cart:
            return Response({"error": "Cart not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CartSerializer(cart)
        return Response(serializer.data)

    def post(self, request):
        """Add product to cart"""
        serializer = CartItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """Clear user's cart"""
        cart = Cart.objects.filter(user=request.user).first()
        if not cart:
            return Response({"error": "Cart not found"}, status=status.HTTP_404_NOT_FOUND)
        cart.cart_items.all().delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------- ORDER VIEWS ----------------
class OrderListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve orders for logged-in user"""
        orders = Order.objects.filter(user=request.user)
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)

    def post(self, request):
        """Create a new order"""
        serializer = OrderSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OrderRetrieveUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, order_id):
        try:
            return Order.objects.get(id=order_id, user=self.request.user)
        except Order.DoesNotExist:
            return None

    def get(self, request, order_id):
        """Retrieve an order by ID"""
        order = self.get_object(order_id)
        if not order:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = OrderSerializer(order)
        return Response(serializer.data)

    def put(self, request, order_id):
        """Update an order"""
        order = self.get_object(order_id)
        if not order:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = OrderSerializer(order, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, order_id):
        """Cancel an order"""
        order = self.get_object(order_id)
        if not order:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
        order.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CartItemListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve all items in the user's cart"""
        cart = Cart.objects.filter(user=request.user).first()
        if not cart:
            return Response({"error": "Cart not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CartItemSerializer(cart.items.all(), many=True)
        return Response(serializer.data)

    # def post(self, request):
    #     """Add a product to the cart"""
    #     print("Request data:", request.data)  # Debugging line
    #     cart, created = Cart.objects.get_or_create(user=request.user)
    #     request.data["cart"] = cart.id  # Associate cart with the logged-in user

    #     serializer = CartItemSerializer(data=request.data)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data, status=status.HTTP_201_CREATED)
        
    #     print("Serializer errors:", serializer.errors)  # Debugging line
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def post(self, request):
        """Add a product to the cart or update quantity if it already exists"""
        cart, created = Cart.objects.get_or_create(user=request.user)
        request.data["cart"] = cart.id  # Associate cart with the logged-in user

        product_id = request.data.get("product")
        quantity = request.data.get("quantity", 1)
        is_selected = request.data.get("is_selected", False)  # Default to False if missing

        if not product_id:
            return Response({"error": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the product already exists in the cart
        existing_item = CartItem.objects.filter(cart=cart, product_id=product_id).first()

        if existing_item:
            # Update quantity and is_selected
            existing_item.quantity += quantity
            existing_item.is_selected = is_selected  # Explicitly set is_selected
            existing_item.save()
            serializer = CartItemSerializer(existing_item)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # Create a new cart item
            serializer = CartItemSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class CartItemRetrieveUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, cart_item_id, user):
        try:
            return CartItem.objects.get(id=cart_item_id, cart__user=user)
        except CartItem.DoesNotExist:
            return None

    def get(self, request, cart_item_id):
        """Retrieve a specific cart item"""
        cart_item = self.get_object(cart_item_id, request.user)
        if not cart_item:
            return Response({"error": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CartItemSerializer(cart_item)
        return Response(serializer.data)

    def put(self, request, cart_item_id):
        """Update the quantity of a cart item"""
        cart_item = self.get_object(cart_item_id, request.user)
        if not cart_item:
            return Response({"error": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CartItemSerializer(cart_item, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, cart_item_id):
        """Remove a cart item"""
        cart_item = self.get_object(cart_item_id, request.user)
        if not cart_item:
            return Response({"error": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
        cart_item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrderItemListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, order_id):
        """Retrieve all items for a specific order"""
        order = Order.objects.filter(id=order_id, user=request.user).first()
        if not order:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = OrderItemSerializer(order.items.all(), many=True)
        return Response(serializer.data)


class OrderItemRetrieveUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, order_item_id, user):
        try:
            return OrderItem.objects.get(id=order_item_id, order__user=user)
        except OrderItem.DoesNotExist:
            return None

    def get(self, request, order_item_id):
        """Retrieve a specific order item"""
        order_item = self.get_object(order_item_id, request.user)
        if not order_item:
            return Response({"error": "Order item not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = OrderItemSerializer(order_item)
        return Response(serializer.data)

    def put(self, request, order_item_id):
        """Update an order item (Admins only)"""
        order_item = self.get_object(order_item_id, request.user)
        if not order_item:
            return Response({"error": "Order item not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = OrderItemSerializer(order_item, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, order_item_id):
        """Remove an order item (Admins only)"""
        order_item = self.get_object(order_item_id, request.user)
        if not order_item:
            return Response({"error": "Order item not found"}, status=status.HTTP_404_NOT_FOUND)
        order_item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class AddressListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """View all addresses of the authenticated user."""
        addresses = Address.objects.filter(user=request.user)
        serializer = AddressSerializer(addresses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Add a new address for the authenticated user."""
        data = request.data.copy()
        data['user'] = request.user.id  # Extract user ID from JWT token
        serializer = AddressSerializer(data=data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AddressUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, address_id):
        """Update an existing address."""
        try:
            address = Address.objects.get(id=address_id, user=request.user)
        except Address.DoesNotExist:
            return Response({"error": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AddressSerializer(address, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, address_id):
        """Delete an address."""
        try:
            address = Address.objects.get(id=address_id, user=request.user)
        except Address.DoesNotExist:
            return Response({"error": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

        address.delete()
        return Response({"message": "Address deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Blog
from .serializers import BlogSerializer
from .permissions import IsAuthorOrReadOnly
from django.shortcuts import get_object_or_404

class BlogListCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        blogs = Blog.objects.all().order_by('-date_published')
        serializer = BlogSerializer(blogs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = BlogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BlogDetailAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAuthorOrReadOnly]

    def get_object(self, pk):
        blog = get_object_or_404(Blog, pk=pk)
        self.check_object_permissions(self.request, blog)
        return blog

    def get(self, request, pk):
        blog = self.get_object(pk)
        serializer = BlogSerializer(blog)
        return Response(serializer.data)

    def put(self, request, pk):
        blog = self.get_object(pk)
        serializer = BlogSerializer(blog, data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)  # Ensure author stays same
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        blog = self.get_object(pk)
        blog.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import LightScheduleSerializer
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied, ValidationError
from .models import LightSchedule, Device, Crop
from django.db import IntegrityError
from django.http import Http404

from rest_framework.exceptions import PermissionDenied, NotFound

from django.utils import timezone
import paho.mqtt.client as mqtt
from django.conf import settings
import json
import logging

from .models import LightSchedule, Device, Crop
from .serializers import LightScheduleSerializer

logger = logging.getLogger('mqtt')

# MQTT Client setup
mqtt_client = mqtt.Client(client_id="django_light_schedule_publisher")
mqtt_client.username_pw_set(settings.MQTT_USER, settings.MQTT_PASSWORD)
mqtt_client.tls_set()  # Enable TLS
mqtt_client.connect(settings.MQTT_BROKER, settings.MQTT_PORT)
mqtt_client.loop_start()

class LightScheduleListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        schedules = LightSchedule.objects.filter(device__owner=request.user)
        serializer = LightScheduleSerializer(schedules, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        device_id = request.data.get('device')
        if not device_id:
            return Response(
                {"detail": "Device ID is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            device = Device.objects.get(pk=device_id)
        except Device.DoesNotExist:
            return Response(
                {"detail": f"Device with ID {device_id} does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if device.owner != request.user:
            return Response(
                {"detail": "You don't own this device"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = LightScheduleSerializer(
            data=request.data,
            context={'request': request, 'device': device}
        )
        
        if serializer.is_valid():
            if not serializer.validated_data.get('handled_by_user', False):
                self._handle_automatic_scheduling(serializer)
            
            try:
                instance = serializer.save(device=device)
                self._publish_schedule_update(instance)
                return Response(
                    LightScheduleSerializer(instance).data,
                    status=status.HTTP_201_CREATED
                )
            except IntegrityError as e:
                return Response(
                    {"error": str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _handle_automatic_scheduling(self, serializer):
        """Helper method to handle automatic scheduling logic"""
        first_crop = Crop.objects.first()
        if first_crop and first_crop.required_light_duration:
            hours = first_crop.required_light_duration
            serializer.validated_data['schedule_for_week'] = {
                'monday': hours,
                'tuesday': hours,
                'wednesday': hours,
                'thursday': hours,
                'friday': hours,
                'saturday': hours,
                'sunday': hours
            }

    def _publish_schedule_update(self, schedule):
        """Publish schedule updates to MQTT"""
        topic = f"devices/{schedule.device.din}/light_schedule"
        payload = {
            "type": "light_schedule_update",
            "data": LightScheduleSerializer(schedule).data,
            "timestamp": timezone.now().isoformat()
        }
        
        try:
            mqtt_client.publish(
                topic,
                json.dumps(payload),
                qos=1,
                retain=True
            )
            logger.info(f"Published light schedule update to {topic}")
        except Exception as e:
            logger.error(f"Failed to publish MQTT message: {e}")


class LightScheduleRetrieveUpdateDestroyAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, user):
        try:
            schedule = LightSchedule.objects.get(pk=pk)
            if schedule.device.owner != user:
                raise PermissionDenied("You don't own this device")
            return schedule
        except LightSchedule.DoesNotExist:
            raise NotFound(f"No LightSchedule found with id {pk}")

    def get(self, request, pk):
        try:
            schedule = self.get_object(pk, request.user)
            serializer = LightScheduleSerializer(schedule, context={'request': request})
            return Response(serializer.data)
        except NotFound as e:
            return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied as e:
            return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, pk):
        try:
            schedule = self.get_object(pk, request.user)
            serializer = LightScheduleSerializer(
                schedule, 
                data=request.data, 
                context={'request': request}
            )
            
            if serializer.is_valid():
                if 'device' in request.data and request.data['device'] != schedule.device.id:
                    return Response(
                        {"detail": "Cannot change device reference for an existing schedule"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                if not serializer.validated_data.get('handled_by_user', False):
                    self._handle_automatic_scheduling(serializer)
                
                serializer.save()
                self._publish_schedule_update(serializer.instance)
                return Response(serializer.data)
                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except NotFound as e:
            return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied as e:
            return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def patch(self, request, pk):
        try:
            schedule = self.get_object(pk, request.user)
            serializer = LightScheduleSerializer(
                schedule, 
                data=request.data, 
                partial=True,
                context={'request': request}
            )
            
            if serializer.is_valid():
                if 'device' in request.data and request.data['device'] != schedule.device.id:
                    return Response(
                        {"detail": "Cannot change device reference for an existing schedule"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                if not serializer.validated_data.get('handled_by_user', False):
                    self._handle_automatic_scheduling(serializer)
                
                serializer.save()
                self._publish_schedule_update(serializer.instance)
                return Response(serializer.data)
                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except NotFound as e:
            return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied as e:
            return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, pk):
        try:
            schedule = self.get_object(pk, request.user)
            device_din = schedule.device.din
            schedule.delete()
            
            # Publish deletion
            topic = f"device/{device_din}/light_schedule"
            try:
                mqtt_client.publish(
                    topic,
                    "",
                    qos=1,
                    retain=True
                )
                logger.info(f"Published light schedule deletion to {topic}")
            except Exception as e:
                logger.error(f"Failed to publish MQTT deletion message: {e}")
                
            return Response(status=status.HTTP_204_NO_CONTENT)
            
        except NotFound as e:
            return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied as e:
            return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def _handle_automatic_scheduling(self, serializer):
        """Helper method to handle automatic scheduling logic"""
        first_crop = Crop.objects.first()
        if first_crop and first_crop.required_light_duration:
            hours = first_crop.required_light_duration
            serializer.validated_data['schedule_for_week'] = {
                'monday': hours,
                'tuesday': hours,
                'wednesday': hours,
                'thursday': hours,
                'friday': hours,
                'saturday': hours,
                'sunday': hours
            }

    def _publish_schedule_update(self, schedule):
        """Publish schedule updates to MQTT"""
        topic = f"device/{schedule.device.din}/light_schedule"
        payload = {
            "type": "light_schedule_update",
            "data": LightScheduleSerializer(schedule).data,
            "timestamp": timezone.now().isoformat()
        }
        
        try:
            mqtt_client.publish(
                topic,
                json.dumps(payload),
                qos=1,
                retain=True
            )
            logger.info(f"Published light schedule update to {topic}")
        except Exception as e:
            logger.error(f"Failed to publish MQTT message: {e}")

# class LightScheduleListCreateAPIView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         schedules = LightSchedule.objects.filter(device__owner=request.user)
#         serializer = LightScheduleSerializer(schedules, many=True, context={'request': request})
#         return Response(serializer.data)

#     def post(self, request):
#         # Ensure device exists and user owns it first
#         device_id = request.data.get('device')
#         if not device_id:
#             return Response(
#                 {"detail": "Device ID is required"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
        
#         try:
#             device = Device.objects.get(pk=device_id)
#         except Device.DoesNotExist:
#             return Response(
#                 {"detail": f"Device with ID {device_id} does not exist"},
#                 status=status.HTTP_404_NOT_FOUND
#             )
        
#         if device.owner != request.user:
#             return Response(
#                 {"detail": "You don't own this device"},
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         # Now handle the schedule creation
#         serializer = LightScheduleSerializer(
#             data=request.data,
#             context={'request': request, 'device': device}  # Pass device in context
#         )
        
#         if serializer.is_valid():
#             try:
#                 # Explicitly set the device before saving
#                 instance = serializer.save(device=device)
#                 return Response(
#                     LightScheduleSerializer(instance).data,
#                     status=status.HTTP_201_CREATED
#                 )
#             except IntegrityError as e:
#                 return Response(
#                     {"error": str(e)},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def _handle_automatic_scheduling(self, serializer):
#         """Helper method to handle automatic scheduling logic"""
#         first_crop = Crop.objects.first()
#         if first_crop and first_crop.required_light_duration:
#             hours = first_crop.required_light_duration
#             serializer.validated_data['schedule_for_week'] = {
#                 'monday': hours,
#                 'tuesday': hours,
#                 'wednesday': hours,
#                 'thursday': hours,
#                 'friday': hours,
#                 'saturday': hours,
#                 'sunday': hours
#             }


# class LightScheduleRetrieveUpdateDestroyAPIView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get_object(self, pk, user):
#         try:
#             schedule = LightSchedule.objects.get(pk=pk)
#             if schedule.device.owner != user:
#                 raise PermissionDenied("You don't own this device")
#             return schedule
#         except LightSchedule.DoesNotExist:
#             raise Http404(f"No LightSchedule found with id {pk}")

#     def get(self, request, pk):
#         try:
#             schedule = self.get_object(pk, request.user)
#             serializer = LightScheduleSerializer(schedule, context={'request': request})
#             return Response(serializer.data)
#         except Http404 as e:
#             return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
#         except PermissionDenied as e:
#             return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)
        

#     def put(self, request, pk):
#         try:
#             schedule = self.get_object(pk, request.user)
#             #schedule = self.get(request, pk)
#             serializer = LightScheduleSerializer(
#                 schedule, 
#                 data=request.data, 
#                 context={'request': request}
#             )
            
#             if serializer.is_valid():
#                 # Prevent changing the device reference
#                 if 'device' in request.data and request.data['device'] != schedule.device.id:
#                     return Response(
#                         {"detail": "Cannot change device reference for an existing schedule"},
#                         status=status.HTTP_400_BAD_REQUEST
#                     )
                
#                 # Handle automatic scheduling
#                 if not serializer.validated_data.get('handled_by_user', False):
#                     self._handle_automatic_scheduling(serializer)
                
#                 serializer.save()
#                 return Response(serializer.data)
                
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
#         except Http404 as e:
#             return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
#         except PermissionDenied as e:
#             return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)

#     def patch(self, request, pk):
#         try:
#             schedule = self.get_object(pk, request.user)
#             serializer = LightScheduleSerializer(
#                 schedule, 
#                 data=request.data, 
#                 partial=True,
#                 context={'request': request}
#             )
            
#             if serializer.is_valid():
#                 # Prevent changing the device reference
#                 if 'device' in request.data and request.data['device'] != schedule.device.id:
#                     return Response(
#                         {"detail": "Cannot change device reference for an existing schedule"},
#                         status=status.HTTP_400_BAD_REQUEST
#                     )
                
#                 # Handle automatic scheduling
#                 if not serializer.validated_data.get('handled_by_user', False):
#                     self._handle_automatic_scheduling(serializer)
                
#                 serializer.save()
#                 return Response(serializer.data)
                
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
#         except Http404 as e:
#             return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
#         except PermissionDenied as e:
#             return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)

#     def delete(self, request, pk):
#         try:
#             schedule = self.get_object(pk, request.user)
#             schedule.delete()
#             return Response(status=status.HTTP_204_NO_CONTENT)
#         except Http404 as e:
#             return Response({"detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
#         except PermissionDenied as e:
#             return Response({"detail": str(e)}, status=status.HTTP_403_FORBIDDEN)

#     def _handle_automatic_scheduling(self, serializer):
#         """Helper method to handle automatic scheduling logic"""
#         first_crop = Crop.objects.first()
#         if first_crop and first_crop.required_light_duration:
#             hours = first_crop.required_light_duration
#             serializer.validated_data['schedule_for_week'] = {
#                 'monday': hours,
#                 'tuesday': hours,
#                 'wednesday': hours,
#                 'thursday': hours,
#                 'friday': hours,
#                 'saturday': hours,
#                 'sunday': hours
#             }