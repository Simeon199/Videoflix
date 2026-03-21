import os
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse, Http404
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from auth_app.api.authentication import CookieJWTAuthentication
from video_app.models import Video
from video_app.api.serializers import VideoSerializer

class VideoListView(generics.ListAPIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VideoSerializer
    queryset = Video.objects.all().order_by("-created_at")

class HLSManifestView(APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, movie_id, resolution):
        cache_key = f"hls_manifest_{movie_id}_{resolution}"
        cached_content = cache.get(cache_key)

        if cached_content:
            return HttpResponse(cached_content, content_type="application/vnd.apple.mpegurl")
        
        file_path = os.path.join(
            settings.MEDIA_ROOT, "videos", str(movie_id), resolution, "index.m3u8"
        )

        if not os.path.exists(file_path):
            raise Http404("Video nicht gedunden.")
        
        with open(file_path, "r") as f:
            content = f.read()

        cache.set(cache_key, content, timeout=300)
        return HttpResponse(content, content_type="application/vnd.apple.mpegurl")