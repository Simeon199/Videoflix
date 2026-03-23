"""
Serializers for video API endpoints.

This module provides serializers for converting Video model instances
to and from JSON format for API responses.
"""
from rest_framework import serializers
from video_app.models import Video


class VideoSerializer(serializers.ModelSerializer):
    """
    Serializer for Video model.
    Converts Video model instances to JSON format for API responses.
    Includes a computed thumbnail_url field that builds the absolute URI
    based on the current request context.
    Attributes:
        thumbnail_url (SerializerMethodField): Computed field that generates
            the absolute URL for the video thumbnail.
    """
    thumbnail_url = serializers.SerializerMethodField()

    class Meta:
        model = Video
        fields = [
            "id",
            "created_at",
            "title",
            "description",
            "thumbnail_url",
            "category"
        ]

    def get_thumbnail_url(self, obj):
        """
        Generate the absolute URL for a video thumbnail.
        Constructs the absolute URL for the video's thumbnail image based on
        the current request context. Returns None if the thumbnail doesn't exist
        or if the request context is not available.
        Args:
            obj (Video): The Video model instance being serialized.
        Returns:
            str or None: The absolute URL to the thumbnail image, or None if
                not available.
        """
        request = self.context.get("request")
        if obj.thumbnail and request:
            return request.build_absolute_uri(obj.thumbnail.url)
        return None