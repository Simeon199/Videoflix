from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from auth_app.api.authentication import CookieJWTAuthentication
from video_app.models import Video
from video_app.api.serializers import VideoSerializer

class VideoListView(generics.ListAPIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VideoSerializer
    queryset = Video.objects.all().order_by("-created_at")