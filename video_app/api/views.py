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
    
    def _get_manifest_file_path(self, movie_id, resolution):
        return os.path.join(
            settings.MEDIA_ROOT, "videos", str(movie_id), resolution, "index.m3u8"
        )
    
    def _get_cached_or_read_manifest(self, cache_key, file_path):
        cached_content = cache.get(cache_key)
        if cached_content:
            return cached_content
        
        if not os.path.exists(file_path):
            return None
        
        with open(file_path, "r") as f:
            return f.read()
    
    def _return_manifest(self, cache_key, content):
        cache.set(cache_key, content, timeout=300)
        return HttpResponse(content, content_type="application/vnd.apple.mpegurl")

    def get(self, request, movie_id, resolution):
        cache_key = f"hls_manifest_{movie_id}_{resolution}"
        file_path = self._get_manifest_file_path(movie_id, resolution)
        content = self._get_cached_or_read_manifest(cache_key, file_path)
        
        if not content:
            raise Http404("Video nicht gedunden.")
        
        return self._return_manifest(cache_key, content)
    
class HLSSegmentView(APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def _get_segment_file_path(self, movie_id, resolution, segment):
        return os.path.join(
            settings.MEDIA_ROOT, "videos", str(movie_id), resolution, segment
        )
    
    def _load_segment_content(self, file_path):
        if not os.path.exists(file_path):
            return None
        
        with open(file_path, "rb") as f:
            return f.read()

    def get(self, request, movie_id, resolution, segment):
        file_path = self._get_segment_file_path(movie_id, resolution, segment)
        content = self._load_segment_content(file_path)
        
        if not content:
            raise Http404("Video oder Segment nicht gefunden.")
        
        return HttpResponse(content, content_type="video/MP2T")