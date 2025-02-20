from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

User = get_user_model()

class LoginView(APIView):
    def post(self, request):
        # Extract username and password from request data
        username = request.data.get("username")
        password = request.data.get("password")
        
        if not username or not password:
            return Response(
                {"error": "Username and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate credentials using Django's authentication framework
        user = authenticate(username=username, password=password)
        if user is None:
            return Response(
                {"error": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Generate JWT tokens for the authenticated user
        access_token = AccessToken.for_user(user)
        refresh_token = RefreshToken.for_user(user)
        
        # Create a response with token details
        response = Response(
            {
                "access": str(access_token),
                "refresh": str(refresh_token)
            },
            status=status.HTTP_200_OK
        )
        
        # Set HTTP-only cookies for the tokens
        response.set_cookie(
            key='access_token',
            value=str(access_token),
            httponly=True,
            secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh_token),
            httponly=True,
            secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
        )
        return response

class RefreshTokenView(APIView):
    def post(self, request):
        # Retrieve the refresh token from cookies
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response(
                {"error": "Refresh token not provided."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Validate the refresh token and decode its payload
            token = RefreshToken(refresh_token)
            # Option 1: Directly use the refresh token to create a new access token
            access_token = AccessToken.for_user(User.objects.get(id=token.payload.get("user_id")))
        except Exception:
            return Response(
                {"error": "Invalid refresh token."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Prepare a new response with the refreshed access token
        response = Response(
            {"access": str(access_token)},
            status=status.HTTP_200_OK
        )
        response.set_cookie(
            key='access_token',
            value=str(access_token),
            httponly=True,
            secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
        )
        return response

