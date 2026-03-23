from django.db.models.signals import post_save
from django.dispatch import receiver
from video_app.models import Video
from video_app.tasks import convert_to_hls

@receiver(post_save, sender=Video)
def video_post_save(sender, instance, created, **kwargs):
    if created and instance.video_file:
        import django_rq
        queue = django_rq.get_queue('default')
        queue.enqueue(convert_to_hls, instance.id)