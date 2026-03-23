import os
import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from video_app.models import Video

@pytest.fixture
def create_user(db):
    def _create_user(email="test@example.com", password="securePass123!", is_active=True):
        return User.objects.create_user(
            username=email,
            email=email,
            password=password,
            is_active=is_active
        )
    return create_user

@pytest.fixture
def sample_thumbnail():
    jpeg_bytes = (
        b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        b'\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t'
        b'\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a'
        b'\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'9=82<.342'
        b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'
        b'\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b'
        b'\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04'
        b'\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07'
        b'"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17'
        b'\x18\x19\x1a%&\'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84'
        b'\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2'
        b'\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9'
        b'\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7'
        b'\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3'
        b'\xf4\xf5\xf6\xf7\xf8\xf9\xfa'
        b'\xff\xda\x00\x08\x01\x01\x00\x00?\x00T\xdb\x9e\xa3\xa1\xac\xaf'
        b'\xff\xd9'
    )
    return SimpleUploadedFile("test.jpg", jpeg_bytes, content_type="image/jpeg")

@pytest.fixture
def create_video(db, sample_thumbnail):
    def _create_video(title="Test Movie", description="Test Description", category="Drama"):
        return Video.objects.create(
            title=title,
            description=description,
            thumbnail=sample_thumbnail,
            category=category
        )
    return _create_video

@pytest.fixture
def hls_video_files(db, create_video, tmp_path, monkeypatch):
    video = create_video(title="HLS Test Film")

    # Redirect MEDIA_ROOT to tmp_path
    monkeypatch.setattr(settings, "MEDIA_ROOT", str(tmp_path))

    video_dir = tmp_path / "videos" / str(video.id) / "480p"
    video_dir.mkdir(parents=True)

    manifest_content = "#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:10.0,\n000.ts\n#EXT-X-ENDLIST\n"
    (video_dir / "index.m3u8").write_text(manifest_content)
    (video_dir / "000.ts").write_bytes(b"\x00"*188) 

    return video, "480p", manifest_content