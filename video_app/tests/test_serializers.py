import pytest
from rest_framework.test import APIRequestFactory
from video_app.api.serializers import VideoSerializer
from video_app.models import Video

@pytest.mark.django_db
class TestVideoSerializer:

    def test_contains_expected_fields(self, create_video):
        video = create_video()
        factory = APIRequestFactory()
        request = factory.get("api/video/")
        serializer = VideoSerializer(video, context={"request": request})

        assert set(serializer.data.keys()) == {
            "id", "created_at", "title", "description", "thumbnail_url", "category"
        }

    def test_title_field_content(self, create_video):
        video = create_video(title="My Movie")
        serializer = VideoSerializer(video)
        assert serializer.data["title"] == "My Movie"

    def test_description_field_content(self, create_video):
        video = create_video(description="A great film")
        serializer = VideoSerializer(video)
        assert serializer.data["description"] == "A great film"

    def test_category_field_content(self, create_video):
        video = create_video(category="Romance")
        serializer = VideoSerializer(video)
        assert serializer.data["category"] == "Romance"

    def test_thumbnail_url_is_absolute(self, create_video):
        video = create_video()
        factory = APIRequestFactory()
        request = factory.get("/api/video/")
        serializer = VideoSerializer(video, context={"request": request})
        
        assert serializer.data["thumbnail_url"].startswith("http")
        assert "/media/thumbnails/" in serializer.data["thumbnail_url"]

    def test_thumbnail_none_without_request(self, create_video):
        video = create_video()
        serializer = VideoSerializer(video)
        assert serializer.data["thumbnail_url"] is None

    def test_created_at_is_present(self, create_video):
        video = create_video()
        serializer = VideoSerializer(video)
        assert serializer.data["created_at"] is not None

    def test_serializes_multiple_videos(self, create_video):
        create_video(title="Film 1")
        create_video(title="Film 2")
        videos = Video.objects.all()
        serializer = VideoSerializer(videos, many=True)
        assert len(serializer.data) == 2