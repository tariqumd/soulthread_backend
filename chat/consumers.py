import json
from channels.generic.websocket import AsyncWebsocketConsumer

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # This is the room group name, can be dynamic based on the room name
        self.room_group_name = "soulthread"

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,  # Room name (group)
            self.channel_name      # Channel name (unique identifier for this connection)
        )

        # Accept the WebSocket connection
        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group on disconnect
        await self.channel_layer.group_discard(
            self.room_group_name,  # Room name
            self.channel_name      # Channel name
        )

    async def receive(self, text_data):
        # Handle receiving a message from the WebSocket
        data = json.loads(text_data)  # Parse the incoming message
        message = data["message"]     # Extract the message from the data

        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name,  # Room group to which the message will be sent
            {
                "type": "chat_message",  # Type of message
                "message": message,      # The actual message
            }
        )

    async def chat_message(self, event):
        # This function handles the sending of the message to WebSocket
        message = event["message"] + "Tariq"  # Extract the message from the event

        # Send the message to WebSocket (client)
        await self.send(text_data=json.dumps({
            "message": "tariq" # Send message as JSON
        }))
