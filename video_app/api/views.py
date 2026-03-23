"""
Video API views for HLS streaming and video management.

This module provides API endpoints for video listing and HLS (HTTP Live Streaming)
manifest and segment delivery. All views require authentication via JWT tokens.
"""
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
    """
    API view for retrieving a list of all videos.
    Provides a paginated list of all videos in the system, ordered by
    creation date in descending order (newest first). Requires authentication.
    Attributes:
        authentication_classes: Uses cookie-based JWT authentication.
        permission_classes: Requires authenticated users.
        serializer_class: Uses VideoSerializer for response formatting.
        queryset: Retrieves all videos ordered by creation date.
    """
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VideoSerializer
    queryset = Video.objects.all().order_by("-created_at")

class HLSManifestView(APIView):
    """
    API view for serving HLS manifest files.
    Handles retrieval of HLS manifest files (M3U8) for video streaming.
    Implements caching to improve performance for frequently requested manifests.
    Requires authentication.
    """
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def _get_manifest_file_path(self, movie_id, resolution):
        """
        Construct the file path for a manifest file.
        Args:
            movie_id (int): The ID of the video.
            resolution (str): The streaming resolution (e.g., '360p', '720p', '1080p').
        Returns:
            str: Full path to the manifest file (index.m3u8).
        """
        return os.path.join(
            settings.MEDIA_ROOT, "videos", str(movie_id), resolution, "index.m3u8"
        )
    
    def _get_cached_or_read_manifest(self, cache_key, file_path):
        """
        Retrieve manifest content from cache or read from file.
        First attempts to retrieve the manifest from cache. If not cached,
        reads from the file system and returns the content.
        Args:
            cache_key (str): Cache key for storing/retrieving the manifest.
            file_path (str): Path to the manifest file.
        Returns:
            str or None: Manifest content if found, None if file doesn't exist.
        """
        cached_content = cache.get(cache_key)
        if cached_content:
            return cached_content
        if not os.path.exists(file_path):
            return None
        with open(file_path, "r") as f:
            return f.read()
    
    def _return_manifest(self, cache_key, content):
        """
        Cache manifest content and return HTTP response.
        Stores the manifest content in cache with a 5-minute timeout
        and returns it as an HTTP response.
        Args:
            cache_key (str): Cache key for storing the manifest.
            content (str): Manifest content to cache and return.
        Returns:
            HttpResponse: HLS manifest file with appropriate MIME type.
        """
        cache.set(cache_key, content, timeout=300)
        return HttpResponse(content, content_type="application/vnd.apple.mpegurl")

    def get(self, request, movie_id, resolution):
        """
        Retrieve and serve HLS manifest file.
        GET endpoint that retrieves the HLS manifest file for a specific
        video and resolution. Returns cached content when available.
        Args:
            request: HTTP request object.
            movie_id (int): The ID of the video.
            resolution (str): The streaming resolution.
        Returns:
            HttpResponse: The manifest file content.
        Raises:
            Http404: If the manifest file does not exist.
        """
        cache_key = f"hls_manifest_{movie_id}_{resolution}"
        file_path = self._get_manifest_file_path(movie_id, resolution)
        content = self._get_cached_or_read_manifest(cache_key, file_path)
        if not content:
            raise Http404("Video nicht gefunden.")
        return self._return_manifest(cache_key, content)
    
class HLSSegmentView(APIView):
    """
    API view for serving HLS video segment files.
    Handles retrieval of individual HLS segment files (TS segments) for
    video streaming. Each segment represents a chunk of the video stream.
    Requires authentication.
    """
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def _get_segment_file_path(self, movie_id, resolution, segment):
        """
        Construct the file path for a video segment.
        Args:
            movie_id (int): The ID of the video.
            resolution (str): The streaming resolution (e.g., '360p', '720p', '1080p').
            segment (str): The filename of the segment (e.g., 'segment0.ts').
        Returns:
            str: Full path to the segment file.
        """
        return os.path.join(
            settings.MEDIA_ROOT, "videos", str(movie_id), resolution, segment
        )
    
    def _load_segment_content(self, file_path):
        """
        Load video segment content from file system.
        Reads the binary content of a video segment file.
        Args:
            file_path (str): Path to the segment file.
        Returns:
            bytes or None: Binary content of the segment if found, None otherwise.
        """
        if not os.path.exists(file_path):
            return None
        with open(file_path, "rb") as f:
            return f.read()

    def get(self, request, movie_id, resolution, segment):
        """
        Retrieve and serve HLS video segment file.
        GET endpoint that retrieves a specific video segment for streaming.
        Args:
            request: HTTP request object.
            movie_id (int): The ID of the video.
            resolution (str): The streaming resolution.
            segment (str): The filename of the segment.
        Returns:
            HttpResponse: The video segment file as binary data.
        Raises:
            Http404: If the segment file does not exist.
        """
        file_path = self._get_segment_file_path(movie_id, resolution, segment)
        content = self._load_segment_content(file_path)
        if not content:
            raise Http404("Video oder Segment nicht gefunden.")
        return HttpResponse(content, content_type="video/MP2T")