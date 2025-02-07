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
    ReceiveDeviceData
    )

urlpatterns = [
    #auth
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    #crop
    path('crops/', CropListCreateView.as_view(), name='crop-list-create'),
    path('crops/<int:pk>/', CropRetrieveUpdateDeleteView.as_view(), name='crop-detail'),
    path('get-crop-names/', CropNamesView.as_view(), name='crop-list'),

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

    #todos
    path('todos/', TodoListCreateView.as_view(), name='todo-list-create'),
    path('todos/<int:pk>/', TodoRetrieveUpdateDeleteView.as_view(), name='todo-detail'),
    path('todos/list-todos/', UserTodoListView.as_view(), name='user_todos'),
    path('todos/mark-done/<int:pk>/', MarkTodoDoneView.as_view(), name='mark_todo_done'),
]

