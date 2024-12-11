from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from chat.models import Message
from django.contrib.auth import get_user_model
from chat.serializers import MessageSerializer, LoginSerializer, RegistrationSerializer
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework import serializers
from transformers import pipeline

# Load the pre-trained model from Hugging Face (or another model you prefer)
model = pipeline('text-generation', model="facebook/blenderbot-400M-distill")

User = get_user_model()  # Get the custom user model

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            try:
                # Use the custom user model instead of auth.User
                user = User.objects.get(username=username)

                if user.check_password(password):  # Verify the password
                    # Generate JWT tokens
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    })
                else:
                    return Response({'detail': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

            except User.DoesNotExist:
                return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RegistrationView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  # Save the user using the serializer
            return Response({
                "message": "User registered successfully!",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class MessageList(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        messages = Message.objects.filter(sender=request.user) | Message.objects.filter(receiver=request.user)
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(sender=request.user)
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

class ChatView(APIView):
    def post(self, request):
        # Get the user's message from the request
        user_message = request.data.get("message")

        if not user_message:
            return Response({"error": "No message provided"}, status=400)

        # Generate a response using the model
        # Set truncation=True explicitly to ensure long inputs are truncated
        response = model(user_message, 
                          max_length=1000, 
                          pad_token_id=50256, 
                          truncation=True)  # Explicit truncation

        # Extract the text from the response (DialoGPT generates a list of dictionaries)
        print("response", response)
        bot_reply = response[0]['generated_text']

        # Send the bot's reply as a response
        return Response({"reply": bot_reply})

class LogoutView(APIView):
    def post(self, request):
        try:
            # Extract the refresh token from the request data
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"detail": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Blacklist the token
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
