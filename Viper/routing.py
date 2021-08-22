from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import path

from WebSocket.views import MsfConsoleView, HeartBeatView

websocket_urlpatterns = [
    path('ws/v1/websocket/msfconsole/', MsfConsoleView.as_asgi()),
    path('ws/v1/websocket/heartbeat/', HeartBeatView.as_asgi()),
]

application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})
