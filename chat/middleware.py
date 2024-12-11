# chat/middleware.py

import json
from channels.auth import AuthMiddlewareStack
from channels.db import database_sync_to_async
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model
from django.http import HttpResponse

User = get_user_model()

class JWTAuthenticationMiddleware:
    def __init__(self, inner):
        self.inner = inner

    def __call__(self, scope):
        # Extract JWT token from the 'Authorization' header
        token = None
        for param in scope.get("headers", []):
            if param[0] == b"authorization":
                token = param[1].decode("utf-8").split(" ")[1]  # Extract token after 'Bearer'
                break
        
        if token is None:
            raise ValueError("JWT token not provided")

        # Verify the token
        try:
            access_token = AccessToken(token)
            user = self.get_user_from_token(access_token)
            scope['user'] = user  # Add user to the WebSocket scope
        except Exception as e:
            raise ValueError("Invalid token or token expired")

        return self.inner(scope)

    @database_sync_to_async
    def get_user_from_token(self, access_token):
        try:
            user = User.objects.get(id=access_token['user_id'])
            return user
        except User.DoesNotExist:
            raise ValueError("User not found")
