from django.urls import path
from .views import (
    SignupView, 
    LoginView,
    CropListCreateView,
    CropRetrieveUpdateDeleteView,
    CropNamesView,
    DeviceCreateRetrieveView,
    DeviceUpdateDeleteView,
    PodCreateRetrieveView,
    PodUpdateDeleteView,
    UserDevicesView,
    DeviceDetailByNameView,
    TodoListCreateView,
    TodoRetrieveUpdateDeleteView,
    UserTodoListView,
    MarkTodoDoneView,
    TokenRefreshView,
    ReceiveDeviceData,
    AdminLoginView,
    AdminSignupView,
    GetUserDataView,
    UpdateUserInfoView,
    CategoryListCreateView, CategoryRetrieveUpdateDeleteView,
    ProductListCreateView, ProductRetrieveUpdateDeleteView,
    CartListCreateView, CartItemListCreateView, CartItemRetrieveUpdateDeleteView,
    OrderListCreateView, OrderRetrieveUpdateDeleteView,
    OrderItemListView, OrderItemRetrieveUpdateDeleteView, AddressListCreateView, AddressUpdateDeleteView,
    BlogListCreateAPIView,BlogDetailAPIView,
    LightScheduleListCreateAPIView, LightScheduleRetrieveUpdateDestroyAPIView,
    ValidDINListCreateView, ValidDINRetrieveUpdateDestroyView,
    SinglePodAuditLogView, DevicePodsAuditLogView,
    )

urlpatterns = [
    #auth
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    #user
    path('get-user-data/', GetUserDataView.as_view(), name='get_user_data'),
    path('update-user-info/', UpdateUserInfoView.as_view(), name='update_user_info'),

    # Admin signup and login URLs
    path('admin/signup/', AdminSignupView.as_view(), name='admin-signup'),
    path('admin/login/', AdminLoginView.as_view(), name='admin-login'),

    #crop
    path('crops/', CropListCreateView.as_view(), name='crop-list-create'),
    path('crops/<int:pk>/', CropRetrieveUpdateDeleteView.as_view(), name='crop-detail'),
    path('get-crop-names/', CropNamesView.as_view(), name='crop-list'),

    #valid dins
    path('valid-dins/', ValidDINListCreateView.as_view(), name='valid-din-list-create'),
    path('valid-dins/<int:pk>/', ValidDINRetrieveUpdateDestroyView.as_view(), name='valid-din-retrieve-destroy'),

    #device
    path('devices/', DeviceCreateRetrieveView.as_view(), name='device-create-retrieve'),  # Create & List
    path('devices/<int:device_id>/', DeviceUpdateDeleteView.as_view(), name='device-update-delete'),  # Update & Delete
    path('devices/get-user-devices/', UserDevicesView.as_view(), name='user-devices'), 
    path('devices/get-device-detail/', DeviceDetailByNameView.as_view(), name='device-detail'),

    #device audit logs
    path('receive-device-data/', ReceiveDeviceData.as_view(), name='receive-device-data'),

    #pod
    path('pods/', PodCreateRetrieveView.as_view(), name='pod-create-retrieve'),  # Create and List Pods
    path('pods/<int:device_id>/', PodUpdateDeleteView.as_view(), name='pod-update-delete'),  # Update and Delete Pods

    #pods audit logs
    path('pods/<int:pod_id>/audit-logs/', SinglePodAuditLogView.as_view(), name='pod-audit-logs'),
    path('devices/<int:device_id>/pods/audit-logs/', DevicePodsAuditLogView.as_view(), name='device-pods-audit-logs'),

    #todos
    path('todos/', TodoListCreateView.as_view(), name='todo-list-create'),
    path('todos/<int:pk>/', TodoRetrieveUpdateDeleteView.as_view(), name='todo-detail'),
    path('todos/list-todos/', UserTodoListView.as_view(), name='user_todos'),
    path('todos/mark-done/<int:pk>/', MarkTodoDoneView.as_view(), name='mark_todo_done'),

    # Category URLs
    path('categories/', CategoryListCreateView.as_view(), name='category-list-create'),
    path('categories/<int:category_id>/', CategoryRetrieveUpdateDeleteView.as_view(), name='category-detail'),

    # Product URLs
    path('products/', ProductListCreateView.as_view(), name='product-list-create'),
    path('products/<int:product_id>/', ProductRetrieveUpdateDeleteView.as_view(), name='product-detail'),

    # Cart URLs
    path('cart/', CartListCreateView.as_view(), name='cart'),
    path('cart/items/', CartItemListCreateView.as_view(), name='cart-item-list-create'),
    path('cart/items/<int:cart_item_id>/', CartItemRetrieveUpdateDeleteView.as_view(), name='cart-item-detail'),

    # Order URLs
    path('orders/', OrderListCreateView.as_view(), name='order-list-create'),
    path('orders/<int:order_id>/', OrderRetrieveUpdateDeleteView.as_view(), name='order-detail'),

    # Order Items URLs
    path('orders/<int:order_id>/items/', OrderItemListView.as_view(), name='order-item-list'),
    path('order-items/<int:order_item_id>/', OrderItemRetrieveUpdateDeleteView.as_view(), name='order-item-detail'),

    #address urls
    path('addresses/', AddressListCreateView.as_view(), name='address-list-create'),
    path('addresses/<int:address_id>/', AddressUpdateDeleteView.as_view(), name='address-update-delete'),

    #blogs
    path('blogs/', BlogListCreateAPIView.as_view(), name='blog-list-create'),
    path('blogs/<int:pk>/', BlogDetailAPIView.as_view(), name='blog-detail'),

    #light schedules
    path('light-schedules/', LightScheduleListCreateAPIView.as_view(), name='light-schedule-list-create'),
    path('light-schedules/<int:pk>/', LightScheduleRetrieveUpdateDestroyAPIView.as_view(), name='light-schedule-retrieve-update-destroy'),
]

