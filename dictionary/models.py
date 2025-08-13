from django.db import models
from django.contrib.auth.models import User
from django.contrib import admin
import openpyxl
from django.http import HttpResponse

class Tool(models.Model):
    name = models.CharField(max_length=255)
    link = models.URLField(max_length=500)
    image_url = models.URLField(max_length=500, blank=True, null=True)
    thumbnail_url = models.URLField(max_length=500, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=True)
    click_count = models.PositiveIntegerField(default=0)
    views = models.PositiveIntegerField(default=0)
    developer = models.CharField(max_length=255, blank=True, null=True)
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    # ✨ New long-form content fields
    overview = models.TextField(blank=True, null=True)
    what_you_can_do_with = models.TextField(blank=True, null=True)
    key_features = models.TextField(blank=True, null=True)
    benefits = models.TextField(blank=True, null=True)
    pricing_plans = models.TextField(blank=True, null=True)
    tips_best_practices = models.TextField(blank=True, null=True)
    faqs = models.TextField(blank=True, null=True)
    final_take = models.TextField(blank=True, null=True)
    pricing = models.TextField(blank=True, null=True)
    rating = models.TextField(blank=True, null=True)
    
    CATEGORY_CHOICES = [
    ('Business & Productivity', 'Business & Productivity'),
    ('Education & Knowledge', 'Education & Knowledge'),
    ('Environmental', 'Environmental'),
    ('Food & Nutrition', 'Food & Nutrition'),
    ('Government & Public Sector', 'Government & Public Sector'),
    ('Health & Wellness', 'Health & Wellness'),
    ('Language & Communication', 'Language & Communication'),
    ('Media & Entertainment', 'Media & Entertainment'),
    ('NFT & Blockchain', 'NFT & Blockchain'),
    ('Personal & Lifestyle', 'Personal & Lifestyle'),
    ('Security & Privacy', 'Security & Privacy'),
    ('Sports', 'Sports'),
    ('Tech & Engineering', 'Tech & Engineering'),
    ('Travel & Navigation', 'Travel & Navigation'),
    ('Utilities & Tools', 'Utilities & Tools'),
    ('Other', 'Other')
    ]

    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='Other')
    
    def __str__(self):
        return self.name
    
class SearchQuery(models.Model):
    query = models.CharField(max_length=255)
    searched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.query
