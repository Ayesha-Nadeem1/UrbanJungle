from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        # Debugging output
        print(f"User: {request.user}")
        print(f"Is Authenticated: {request.user.is_authenticated}")
        print(f"Is Admin: {getattr(request.user, 'is_admin', False)}")

        # Check if the user is authenticated and is an admin
        return request.user and request.user.is_authenticated and getattr(request.user, 'is_admin', False)
