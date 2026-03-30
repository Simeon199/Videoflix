import subprocess
import os
from django.conf import settings
from video_app.models import Video


def _convert_video_to_hls_resolutions(source_path, video_id):
    """
    Convert video to HLS format at multiple resolutions.
    Generates HLS streams at 480p, 720p, and 1080p resolutions.
    For each resolution, creates .m3u8 manifest and .ts segment files.
    Args:
        source_path (str): Path to the source video file.
        video_id (int): The ID of the video for organizing output directories.
    Raises:
        subprocess.CalledProcessError: If FFmpeg encoding fails.
    """
    resolutions = {
        "480p": "854:480",
        "720p": "1280:720",
        "1080p": "1920:1080",
    }

    for name, scale in resolutions.items():
        output_dir = os.path.join(settings.MEDIA_ROOT, "videos", str(video_id), name)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "index.m3u8")
        subprocess.run([
            "ffmpeg", "-i", source_path,
            "-vf", f"scale={scale}",
            "-c:v", "libx264",
            "-c:a", "aac",
            "-start_number", "0",
            "-hls_time", "10",
            "-hls_list_size", "0",
            "-hls_segment_filename", os.path.join(output_dir, "%03d.ts"),
            "-f", "hls",
            output_path
        ], check=True)


def _generate_video_thumbnail(source_path, video_id, video):
    """
    Generate a thumbnail image from the video.
    Extracts a single frame from 10 seconds into the video and saves it
    as a JPEG thumbnail. Updates the video model with the thumbnail path.
    Args:
        source_path (str): Path to the source video file.
        video_id (int): The ID of the video for organizing output files.
        video (Video): The Video model instance to update with thumbnail.
    Raises:
        subprocess.CalledProcessError: If FFmpeg thumbnail extraction fails.
    """
    thumbnail_dir = os.path.join(settings.MEDIA_ROOT, "thumbnails")
    os.makedirs(thumbnail_dir, exist_ok=True)
    thumbnail_filename = f"{video_id}.jpg"
    thumbnail_path = os.path.join(thumbnail_dir, thumbnail_filename)
    subprocess.run([
        "ffmpeg", "-y", "-i", source_path,
        "-ss", "00:00:10",
        "-vframes", "1",
        "-q:v", "2",
        thumbnail_path
    ], check=True)

    video.thumbnail.name = f"thumbnails/{thumbnail_filename}"
    video.save(update_fields=["thumbnail"])


def convert_to_hls(video_id):
    """
    Convert a video to HLS (HTTP Live Streaming) format for adaptive playback.
    Orchestrates the video processing pipeline: retrieves the video, converts it
    to HLS format at multiple resolutions (480p, 720p, 1080p), and generates a
    thumbnail image. Uses FFmpeg for all encoding operations.
    Args:
        video_id (int): The ID of the Video object to process.
    Raises:
        subprocess.CalledProcessError: If FFmpeg commands fail.
        Video.DoesNotExist: If video with given ID doesn't exist.
    Returns:
        None
    """
    video = Video.objects.get(id=video_id)
    source_path = video.video_file.path
    _convert_video_to_hls_resolutions(source_path, video_id)
    _generate_video_thumbnail(source_path, video_id, video)