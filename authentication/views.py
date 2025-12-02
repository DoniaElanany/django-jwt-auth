from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from .models import CustomUser

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = authenticate(username=email, password=password)
        
        if user is None:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)
    
class RegisterView(APIView):
    def post(self, request):
        email = request.data.get('email')
        name = request.data.get('name')
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')
        
        if not email or not name or not phone_number or not password:
            return Response(
                {'error': 'All fields are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if CustomUser.objects.filter(email=email).exists():
            return Response(
                {'error': 'Email already registered'},
                status=status.HTTP_400_BAD_REQUEST
            )
        user = CustomUser.objects.create_user(
            username=email,
            email=email,
            name=name,
            phone_number=phone_number,
            password=password
        )
        return Response(
            {'message': 'User registered successfully'},
            status=status.HTTP_201_CREATED
        )
    
class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = CustomUser.objects.get(email=email)
            
            refresh = RefreshToken.for_user(user)
            reset_token = str(refresh.access_token)
            
            reset_link = f"http://localhost:3000/reset-password?token={reset_token}"
            print(f"\n{'='*50}")
            print(f"PASSWORD RESET LINK FOR: {email}")
            print(f"{reset_link}")
            print(f"{'='*50}\n")
        except CustomUser.DoesNotExist:
            pass
        
        return Response(
            {'message': 'If that email exists, we sent a reset link'},
            status=status.HTTP_200_OK
        )
    
class PasswordResetConfirmView(APIView):
    def post(self, request):
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        
        if not token or not new_password:
            return Response(
                {'error': 'Token and new password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']  

            user = CustomUser.objects.get(id=user_id)
            
            user.set_password(new_password)
            user.save()
            
            return Response(
                {'message': 'Password reset successfully'},
                status=status.HTTP_200_OK
            )
            
        except TokenError:
            return Response(
                {'error': 'Invalid or expired token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )