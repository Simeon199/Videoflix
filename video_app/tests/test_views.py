import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

VIDEO_URL = "/api/video/"


@pytest.fixture
def api_client():
    """
    Fixture providing an unauthenticated API client.
    Returns a fresh APIClient instance for making HTTP requests to the API
    without authentication. Used for testing authentication requirements.
    Returns:
        APIClient: A Django REST framework test client.
    """
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, create_user):
    """
    Fixture providing an authenticated API client.
    Creates a test user and authenticates the API client with that user.
    Used for testing endpoints that require authentication.
    Args:
        api_client: Fixture providing an unauthenticated API client.
        create_user: Fixture factory for creating test user objects.
    Returns:
        APIClient: An authenticated API client with an active test user.
    """
    user = create_user(email="viewer@example.com")
    api_client.force_authenticate(user=user)
    return api_client


# === VideoListView === 

@pytest.mark.django_db
class TestVideoListView:
    """
    Test suite for VideoListView API endpoint.
    Tests the video list endpoint (/api/video/) to verify proper authentication,
    response structure, ordering, and HTTP method restrictions.
    """

    def test_unauthenticated_returns_401(self, api_client):
        """
        Test that unauthenticated requests return 401 Unauthorized.
        Verifies that accessing the video list endpoint without authentication
        returns an HTTP 401 status code.
        Args:
            api_client: Fixture providing an unauthenticated API client.
        """
        response = api_client.get(VIDEO_URL)
        assert response.status_code == 401

    def test_authenticated_returns_200(self, authenticated_client):
        """
        Test that authenticated requests return 200 OK.
        Verifies that authenticated users can access the video list endpoint
        and receive an HTTP 200 status code.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
        """
        response = authenticated_client.get(VIDEO_URL)
        assert response.status_code == 200

    def test_returns_empty_list(self, authenticated_client):
        """
        Test that endpoint returns empty list when no videos exist.
        Verifies that the endpoint returns an empty list when the database
        contains no video records.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
        """
        response = authenticated_client.get(VIDEO_URL)
        assert response.data == []

    def test_returns_all_videos(self, authenticated_client, create_video):
        """
        Test that endpoint returns all created videos.
        Verifies that the endpoint correctly returns all video records
        from the database in the response.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            create_video: Fixture factory for creating test video objects.
        """
        create_video(title="Film A")
        create_video(title="Film B")
        response = authenticated_client.get(VIDEO_URL)
        assert len(response.data) == 2

    def test_response_contains_expected_fields(self, authenticated_client, create_video):
        """
        Test that response contains all expected fields.
        Verifies that each video object in the response includes all required
        fields: id, created_at, title, description, thumbnail_url, and category.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            create_video: Fixture factory for creating test video objects.
        """
        create_video()
        response = authenticated_client.get(VIDEO_URL)
        video = response.data[0]
        assert "id" in video
        assert "created_at" in video
        assert "title" in video
        assert "description" in video
        assert "thumbnail_url" in video
        assert "category" in video

    def test_response_field_values(self, authenticated_client, create_video):
        """
        Test that response fields contain correct values.
        Verifies that the serialized video data contains the correct values
        for title, description, and category fields.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            create_video: Fixture factory for creating test video objects.
        """
        create_video(title="Drama Film", description="A drama movie", category="Drama")
        response = authenticated_client.get(VIDEO_URL)
        video = response.data[0]
        assert video["title"] == "Drama Film"
        assert video["description"] == "A drama movie"
        assert video["category"] == "Drama"

    def test_ordered_by_newest_first(self, authenticated_client, create_video):
        """
        Test that videos are ordered by creation time (newest first).
        Verifies that the endpoint returns videos ordered by created_at
        in descending order (most recent first).
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            create_video: Fixture factory for creating test video objects.
        """
        create_video(title="Older Film")
        create_video(title="Newer Film")
        response = authenticated_client.get(VIDEO_URL)
        assert response.data[0]["title"] == "Newer Film"
        assert response.data[1]["title"] == "Older Film"

    def test_only_get_method_allowed(self, authenticated_client):
        """
        Test that only GET method is allowed on this endpoint.
        Verifies that POST, PUT, and DELETE requests return 405 Method Not Allowed.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
        """
        assert authenticated_client.post(VIDEO_URL, {}, format="json").status_code == 405
        assert authenticated_client.put(VIDEO_URL, {}, format="json").status_code == 405
        assert authenticated_client.delete(VIDEO_URL).status_code == 405


# === HLSManifestView ===

@pytest.mark.django_db
class TestHLSManifestView:
    """
    Test suite for HLSManifestView endpoint.
    Tests the HLS manifest endpoint to verify authentication, manifest delivery,
    caching behavior, proper content types, and HTTP method restrictions.
    Manifests are .m3u8 files that define HLS stream segments.
    """

    def test_unauthenticated_returns_401(self, api_client, create_video):
        """
        Test that unauthenticated requests return 401 Unauthorized.
        Verifies that accessing the HLS manifest endpoint without authentication
        returns an HTTP 401 status code.
        Args:
            api_client: Fixture providing an unauthenticated API client.
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video()
        url = f"/api/video/{video.id}/480p/index.m3u8"
        response = api_client.get(url)
        assert response.status_code == 401

    def test_returns_manifest_for_existing_file(self, authenticated_client, hls_video_files):
        """
        Test that manifest is returned for existing files.
        Verifies that when a valid manifest file exists, the endpoint returns
        HTTP 200 with correct content type and manifest content.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, resolution, manifest_content = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/index.m3u8"
        response = authenticated_client.get(url)
        assert response.status_code == 200
        assert response["Content-Type"] == "application/vnd.apple.mpegurl"
        assert response.content.decode() == manifest_content

    def test_returns_404_for_nonexistent_video(self, authenticated_client):
        """
        Test that 404 is returned for nonexistent video ID.
        Verifies that requesting a manifest for a video that doesn't exist
        returns HTTP 404 Not Found.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
        """
        url = "/api/video/99999/480p/index.m3u8"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_returns_404_for_invalid_resolution(self, authenticated_client, hls_video_files):
        """
        Test that 404 is returned for invalid resolution.
        Verifies that requesting a manifest for a resolution that doesn't exist
        for the video returns HTTP 404 Not Found.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, _, _ = hls_video_files
        url = f"/api/video/{video.id}/360p/index.m3u8"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_manifest_is_cached(self, authenticated_client, hls_video_files):
        """
        Test that manifest content is cached after first request.
        Verifies that the HLS manifest is cached in Django's cache after
        the first successful request to improve performance on subsequent requests.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, resolution, manifest_content = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/index.m3u8"
        cache_key = f"hls_manifest_{video.id}_{resolution}"
        cache.clear()
        assert cache.get(cache_key) is None 
        authenticated_client.get(url)
        assert cache.get(cache_key) == manifest_content 

    def test_only_get_method_allowed(self, authenticated_client, hls_video_files):
        """
        Test that only GET method is allowed on this endpoint.
        Verifies that POST, PUT, and DELETE requests return 405 Method Not Allowed.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/index.m3u8"
        assert authenticated_client.post(url, {}, format="json").status_code == 405
        assert authenticated_client.put(url, {}, format="json").status_code == 405
        assert authenticated_client.delete(url).status_code == 405


# === HLSSegmentView ===

@pytest.mark.django_db
class TestHLSSegmentView:
    """
    Test suite for HLSSegmentView endpoint.
    Tests the HLS segment endpoint to verify authentication, segment delivery,
    proper content types, and HTTP method restrictions. Segments are .ts files
    that contain the actual video data for HLS streaming.
    """

    def test_unauthenticated_returns_401(self, api_client, create_video):
        """
        Test that unauthenticated requests return 401 Unauthorized.
        Verifies that accessing the HLS segment endpoint without authentication
        returns an HTTP 401 status code.
        Args:
            api_client: Fixture providing an unauthenticated API client.
            create_video: Fixture factory for creating test video objects.
        """
        video = create_video()
        url = f"/api/video/{video.id}/480p/000.ts/"
        response = api_client.get(url)
        assert response.status_code == 401

    def test_returns_segment_for_existing_file(self, authenticated_client, hls_video_files):
        """
        Test that segment is returned for existing files.
        Verifies that when a valid segment file exists, the endpoint returns
        HTTP 200 with correct content type and segment binary data.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/000.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 200
        assert response["Content-Type"] == "video/MP2T"
        assert response.content == b"\x00" * 188

    def test_returns_404_for_nonexistent_segment(self, authenticated_client, hls_video_files):
        """
        Test that 404 is returned for nonexistent segment file.
        Verifies that requesting a segment file that doesn't exist
        returns HTTP 404 Not Found.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/999.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_returns_404_for_nonexistent_video(self, authenticated_client):
        """
        Test that 404 is returned for nonexistent video ID.
        Verifies that requesting a segment for a video that doesn't exist
        returns HTTP 404 Not Found.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
        """
        url = "/api/video/99999/480p/000.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_returns_404_for_invalid_resolution(self, authenticated_client, hls_video_files):
        """
        Test that 404 is returned for invalid resolution.
        Verifies that requesting a segment for a resolution that doesn't exist
        for the video returns HTTP 404 Not Found.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, _, _ = hls_video_files
        url = f"/api/video/{video.id}/360p/000.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_only_get_method_allowed(self, authenticated_client, hls_video_files):
        """
        Test that only GET method is allowed on this endpoint.
        Verifies that POST, PUT, and DELETE requests return 405 Method Not Allowed.
        Args:
            authenticated_client: Fixture providing an authenticated API client.
            hls_video_files: Fixture providing HLS video files and metadata.
        """
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/000.ts/"
        assert authenticated_client.post(url, {}, format="json").status_code == 405
        assert authenticated_client.put(url, {}, format="json").status_code == 405
        assert authenticated_client.delete(url).status_code == 405