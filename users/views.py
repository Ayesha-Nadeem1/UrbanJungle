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
    
class DeviceCreateRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Create a new device"""
        # The owner of the device is automatically set as the authenticated user
        serializer = DeviceSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            device = serializer.save(owner=request.user)
            return Response(DeviceSerializer(device).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        """Retrieve a list of devices for the authenticated user"""
        # Retrieve only devices belonging to the authenticated user (owner)
        devices = Device.objects.filter(owner=request.user)
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data)
    
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


class PodCreateRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Create a new pod"""
        din = request.data.get('din')  # Get the device DIN from the request
        if not din:
            return Response({"error": "DIN is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the device and ensure the user is the owner
            device = Device.objects.get(din=din)
            if device.owner != request.user:
                return Response({"error": "You do not own this device."}, status=status.HTTP_403_FORBIDDEN)

            # Add the device to the request data
            request.data['device'] = device.id

            serializer = PodSerializer(data=request.data)
            if serializer.is_valid():
                pod = serializer.save()
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

    def put(self, request, device_id, *args, **kwargs):
        """Update a specific pod of a device"""
        device = self.get_device(device_id, request.user)
        pod_id = request.data.get('pod_id')

        if not pod_id:
            return Response({"error": "Pod ID is required for update."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            pod = Pod.objects.get(id=pod_id, device=device)
            serializer = PodSerializer(pod, data=request.data, partial=True)
            if serializer.is_valid():
                pod = serializer.save()
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
