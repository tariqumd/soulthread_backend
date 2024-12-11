from rest_framework import serializers
from chat.models import Message
from django.contrib.auth import get_user_model

User = get_user_model()  # Get the custom user model


# Serializer for user login
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver', 'content', 'timestamp', 'sentiment']

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'first_name', 'last_name']  # Include other fields if needed

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', None),
            password=validated_data['password'],
            first_name=validated_data.get('first_name',None),
            last_name=validated_data.get('last_name',None)
            
        )
        return user