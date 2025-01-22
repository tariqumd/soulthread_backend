from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from chat.models import Message
from django.contrib.auth import get_user_model
from chat.serializers import MessageSerializer, LoginSerializer, RegistrationSerializer
from rest_framework import status
from transformers import pipeline
import gc

# Initialize the model (update the model and tokenizer paths as needed)
model = pipeline('text-generation', model="distilbert/distilgpt2")

User = get_user_model()

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            try:
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
        messages = (
            Message.objects.filter(sender=request.user) |
            Message.objects.filter(receiver=request.user)
        ).order_by("timestamp")  # Ensure messages are sorted by timestamp

        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(sender=request.user)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChatView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Get the user's message from the request
        user_message = request.data.get("message")

        if not user_message:
            return Response({"error": "No message provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Save the user's message in the database
        Message.objects.create(sender=request.user, receiver="Bot", content=user_message)

        # Fetch the entire conversation of the current user
        conversation = (
            Message.objects.filter(sender=request.user) |
            Message.objects.filter(receiver=request.user)
        ).order_by("timestamp")

        # Format the conversation as a list of message texts
        conversation_texts = [
            f"{'You' if msg.sender == request.user else 'Bot'}: {msg.text}"
            for msg in conversation
        ]

        # Join the conversation texts into a single string
        full_conversation = "\n".join(conversation_texts)

        # Generate a response using the model
        response = model(
            full_conversation,
            max_length=1000,
            pad_token_id=50256,
            truncation=True
        )

        # Extract the bot's reply from the model's response
        bot_reply = response[0]["generated_text"]

        # Save the bot's reply in the database
        Message.objects.create(sender=None, receiver=request.user, text=bot_reply)

        # Send the bot's reply as a response
        return Response({"reply": bot_reply})

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"detail": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)
            
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
