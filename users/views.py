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
                        "message": f"New device '{device.name}' has been added!",
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