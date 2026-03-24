import pytest
from rest_framework.test import APIRequestFactory
from video_app.api.serializers import VideoSerializer
from video_app.models import Video


@pytest.mark.django_db
class TestVideoSerializer:
    """
    Test suite for VideoSerializer.
    Tests the VideoSerializer to ensure it correctly serializes Video model instances,
    validates field presence and content, handles thumbnail URLs properly,
    and supports batch serialization of multiple videos.
    """

    def test_contains_expected_fields(self, create_video):
        """
        Test that serializer contains all expected fields.
        Verifies that the VideoSerializer includes all required fields:
        id, created_at, title, description, thumbnail_url, and category.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video()
        factory = APIRequestFactory()
        request = factory.get("api/video/")
        serializer = VideoSerializer(video, context={"request": request})
        assert set(serializer.data.keys()) == {
            "id", "created_at", "title", "description", "thumbnail_url", "category"
        }

    def test_title_field_content(self, create_video):
        """
        Test that title field is correctly serialized.
        Verifies that the serializer correctly outputs the video title
        with the expected value.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video(title="My Movie")
        serializer = VideoSerializer(video)
        assert serializer.data["title"] == "My Movie"

    def test_description_field_content(self, create_video):
        """
        Test that description field is correctly serialized.
        Verifies that the serializer correctly outputs the video description
        with the expected value.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video(description="A great film")
        serializer = VideoSerializer(video)
        assert serializer.data["description"] == "A great film"

    def test_category_field_content(self, create_video):
        """
        Test that category field is correctly serialized.
        Verifies that the serializer correctly outputs the video category
        with the expected value.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video(category="Romance")
        serializer = VideoSerializer(video)
        assert serializer.data["category"] == "Romance"

    def test_thumbnail_url_is_absolute(self, create_video):
        """
        Test that thumbnail URL is absolute and properly formatted.
        Verifies that when a request context is provided, the thumbnail_url
        field contains an absolute HTTP URL pointing to the media thumbnail path.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video()
        factory = APIRequestFactory()
        request = factory.get("/api/video/")
        serializer = VideoSerializer(video, context={"request": request})
        assert serializer.data["thumbnail_url"].startswith("http")
        assert "/media/thumbnails/" in serializer.data["thumbnail_url"]

    def test_thumbnail_none_without_request(self, create_video):
        """
        Test that thumbnail URL is None without request context.
        Verifies that when no request context is provided to the serializer,
        the thumbnail_url field returns None instead of a relative URL.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video()
        serializer = VideoSerializer(video)
        assert serializer.data["thumbnail_url"] is None

    def test_created_at_is_present(self, create_video):
        """
        Test that created_at timestamp is present in serialized data.
        Verifies that the created_at field is properly serialized and
        contains a non-None timestamp value.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video()
        serializer = VideoSerializer(video)
        assert serializer.data["created_at"] is not None

    def test_serializes_multiple_videos(self, create_video):
        """
        Test that serializer correctly handles multiple video objects.
        Verifies that the serializer with many=True flag correctly serializes
        multiple video instances in a single operation.
        Args:
            create_video: Fixture factory for creating test video objects.
        """
        create_video(title="Film 1")
        create_video(title="Film 2")
        videos = Video.objects.all()
        serializer = VideoSerializer(videos, many=True)
        assert len(serializer.data) == 2