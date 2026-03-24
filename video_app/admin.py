from django.contrib import admin
from video_app.models import Video


@admin.register(Video)
class VideoAdmin(admin.ModelAdmin):
    """
    Admin interface for Video model management.
    Customizes the Django admin interface for the Video model, providing
    an intuitive list view for managing video content with key information
    displayed in columns.
    Attributes:
        list_display (tuple): Tuple of field names to display in the list view.
            - title: Video title
            - category: Video genre/category
            - created_at: Video creation timestamp
    """
    list_display = ('title', 'category', 'created_at')