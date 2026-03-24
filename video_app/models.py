from django.db import models


class Video(models.Model):
    """
    Video model representing a video content in the Videoflix application.
    Stores video metadata including title, description, category, and associated
    files (thumbnail and video file). Videos are categorized by genre for
    organization and discovery.
    
    Attributes:
        CATEGORY_CHOICES (list): Available categories for videos.
        title (CharField): The title of the video (max 150 characters).
        description (TextField): Detailed description of the video content.
        thumbnail (FileField): Video thumbnail image (optional).
        video_file (FileField): The actual video file (optional).
        category (CharField): Genre category of the video.
        created_at (DateTimeField): Timestamp when video was created.
    """
    
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
        """
        Return string representation of the video.
        Returns:
            str: The title of the video.
        """
        return self.title 