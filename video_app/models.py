from django.db import models

class Video(models.Model):
    CATEGORY_CHOICES = [
        ("Drama", "Drama"),
        ("Romance", "Romance"),
        ("Comedy", "Comedy"),
        ("Action", "Action"),
        ("Documentary", "Documentary"),
    ]

    title = models.CharField(max_length=150)
    description = models.TextField()
    thumbnail = models.FileField(upload_to="thumbnails", blank=True, null=True)
    video_file = models.FileField(upload_to="videos/originals", blank=True, null=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title 