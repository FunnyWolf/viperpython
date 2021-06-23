from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import path

from WebSocket.views import MsfConsoleView, HeartBeatView

websocket_urlpatterns = [
    path('ws/v1/websocket/msfconsole/', MsfConsoleView),
    path('ws/v1/websocket/heartbeat/', HeartBeatView),
]

application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})
