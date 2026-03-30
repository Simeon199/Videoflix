import os
import shutil
from django.conf import settings
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from video_app.models import Video
from video_app.tasks import convert_to_hls


@receiver(post_save, sender=Video)
def video_post_save(sender, instance, created, **kwargs):
    """
    Signal handler that triggers HLS conversion when a video is created.
    Listens to the post_save signal from the Video model. When a new Video
    instance with a video_file is created, this handler enqueues a background
    task to convert the video to HLS format for adaptive streaming.
    Args:
        sender (Type): The Video model class that sent the signal.
        instance (Video): The video instance being saved.
        created (bool): True if this is a new instance, False if updating existing.
        **kwargs: Additional keyword arguments from the signal.
    Returns:
        None
    """
    if created and instance.video_file:
        import django_rq
        queue = django_rq.get_queue('default')
        queue.enqueue(convert_to_hls, instance.id)


@receiver(post_delete, sender=Video)
def video_post_delete(sender, instance, **kwargs):
    """
    Signal handler that cleans up media files when a video is deleted.
    Removes the original video file, the HLS directory, and the thumbnail
    from the filesystem to prevent stale files from being reused.
    Args:
        sender (Type): The Video model class that sent the signal.
        instance (Video): The video instance being deleted.
        **kwargs: Additional keyword arguments from the signal.
    Returns:
        None
    """
    if instance.video_file:
        if os.path.isfile(instance.video_file.path):
            os.remove(instance.video_file.path)
    if instance.thumbnail:
        if os.path.isfile(instance.thumbnail.path):
            os.remove(instance.thumbnail.path)
    hls_dir = os.path.join(settings.MEDIA_ROOT, "videos", str(instance.id))
    if os.path.isdir(hls_dir):
        shutil.rmtree(hls_dir)