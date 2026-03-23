import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

VIDEO_URL = "/api/video/"

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def authenticated_client(api_client, create_user):
    user = create_user(email="viewer@example.com")
    api_client.force_authenticate(user=user)
    return api_client

# === VideoListView === 

@pytest.mark.django_db
class TestVideoListView:

    def test_unauthenticated_returns_401(self, api_client):
        response = api_client.get(VIDEO_URL)
        assert response.status_code == 401

    def test_authenticated_returns_200(self, authenticated_client):
        response = authenticated_client.get(VIDEO_URL)
        assert response.status_code == 200

    def test_returns_empty_list(self, authenticated_client):
        response = authenticated_client.get(VIDEO_URL)
        assert response.data == []

    def test_returns_all_videos(self, authenticated_client, create_video):
        create_video(title="Film A")
        create_video(title="Film B")
        response = authenticated_client.get(VIDEO_URL)
        assert len(response.data) == 2

    def test_response_contains_expected_fields(self, authenticated_client, create_video):
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
        create_video(title="Drama Film", description="A drama movie", category="Drama")
        response = authenticated_client.get(VIDEO_URL)
        video = response.data[0]
        assert video["title"] == "Drama Film"
        assert video["description"] == "A drama movie"
        assert video["category"] == "Drama"

    def test_ordered_by_newest_first(self, authenticated_client, create_video):
        create_video(title="Older Film")
        create_video(title="Newer Film")
        response = authenticated_client.get(VIDEO_URL)
        assert response.data[0]["title"] == "Newer Film"
        assert response.data[1]["title"] == "Older Film"

    def test_only_get_method_allowed(self, authenticated_client):
        assert authenticated_client.post(VIDEO_URL, {}, format="json").status_code == 405
        assert authenticated_client.put(VIDEO_URL, {}, format="json").status_code == 405
        assert authenticated_client.delete(VIDEO_URL).status_code == 405

# === HLSManifestView ===

@pytest.mark.django_db
class TestHLSManifestView:

    def test_unauthenticated_returns_401(self, api_client, create_video):
        video = create_video()
        url = f"/api/video/{video.id}/480p/index.m3u8"
        response = api_client.get(url)
        assert response.status_code == 401

    def test_returns_manifest_for_existing_file(self, authenticated_client, hls_video_files):
        video, resolution, manifest_content = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/index.m3u8"
        response = authenticated_client.get(url)
        assert response.status_code == 200
        assert response["Content-Type"] == "application/vnd.apple.mpegurl"
        assert response.content.decode() == manifest_content

    def test_returns_404_for_nonexistent_video(self, authenticated_client):
        url = "/api/video/99999/480p/index.m3u8"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_returns_404_for_invalid_resolution(self, authenticated_client, hls_video_files):
        video, _, _ = hls_video_files
        url = f"/api/video/{video.id}/360p/index.m3u8"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_manifest_is_cached(self, authenticated_client, hls_video_files):
        video, resolution, manifest_content = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/index.m3u8"

        cache_key = f"hls_manifest_{video.id}_{resolution}"
        cache.clear()
        assert cache.get(cache_key) is None # Yet not cached

        authenticated_client.get(url)

        assert cache.get(cache_key) == manifest_content # Now cached

    def test_only_get_method_allowed(self, authenticated_client, hls_video_files):
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/index.m3u8"
        assert authenticated_client.post(url, {}, format="json").status_code == 405
        assert authenticated_client.put(url, {}, format="json").status_code == 405
        assert authenticated_client.delete(url).status_code == 405

# === HLSSegmentView ===

@pytest.mark.django_db
class TestHLSSegmentView:

    def test_unauthenticated_returns_401(self, api_client, create_video):
        video = create_video()
        url = f"/api/video/{video.id}/480p/000.ts/"
        response = api_client.get(url)
        assert response.status_code == 401

    def test_returns_segment_for_existing_file(self, authenticated_client, hls_video_files):
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/000.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 200
        assert response["Content-Type"] == "video/MP2T"
        assert response.content == b"\x00" * 188

    def test_returns_404_for_nonexistent_segment(self, authenticated_client, hls_video_files):
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/999.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_returns_404_for_nonexistent_video(self, authenticated_client):
        url = "/api/video/99999/480p/000.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_returns_404_for_invalid_resolution(self, authenticated_client, hls_video_files):
        video, _, _ = hls_video_files
        url = f"/api/video/{video.id}/360p/000.ts/"
        response = authenticated_client.get(url)
        assert response.status_code == 404

    def test_only_get_method_allowed(self, authenticated_client, hls_video_files):
        video, resolution, _ = hls_video_files
        url = f"/api/video/{video.id}/{resolution}/000.ts/"
        assert authenticated_client.post(url, {}, format="json").status_code == 405
        assert authenticated_client.put(url, {}, format="json").status_code == 405
        assert authenticated_client.delete(url).status_code == 405