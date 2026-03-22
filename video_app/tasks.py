import subprocess
import os
from django.conf import settings
from video_app.models import Video

def convert_to_hls(video_id):
    video = Video.objects.get(id=video_id)
    source_path = video.video_file.path
    resolutions = {
        "480p": "854:480",
        "720p": "1280:720",
        "1080p": "1920:1080",
    }

    for name, scale in resolutions.items():
        output_dir = os.path.join(settings.MEDIA_ROOT, "videos", str(video.id), name)
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