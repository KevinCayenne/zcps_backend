# announcements/serializers.py
from rest_framework import serializers
from .models import Announcement

class AnnouncementSerializer(serializers.ModelSerializer):
    """
    處理公告資料的序列化。
    前端需要同時提供 'content' (JSON) 和 'html_cache' (HTML)。
    """
    class Meta:
        model = Announcement
        fields = (
            'id', 
            'title', 
            'content',       # 接收 Lexical JSON
            'html_cache',    # 接收前端轉換好的 HTML
            'is_active',
            'active_start_time',
            'active_end_time',
            'active_member',
            'is_send_email', 
            'email_sent_at',  # Email 發送時間（只讀）
            'create_time', 
            'update_time'
        )
        read_only_fields = (
            'create_time', 
            'update_time', 
            'active_member', 
            'email_sent_at',  # Email 發送時間為只讀
        )


class ClientAnnouncementSerializer(serializers.ModelSerializer):
    """
    一般會員專用的公告序列化器。
    只包含一般會員需要看到的欄位，不包含管理相關的欄位。
    """
    class Meta:
        model = Announcement
        fields = (
            'id',
            'title',
            'content',       # Lexical JSON 內容
            'html_cache',    # HTML 快取
            'active_start_time',
            'active_end_time',
            'create_time',
        )
        read_only_fields = (
            'id',
            'title',
            'content',
            'html_cache',
            'active_start_time',
            'active_end_time',
            'create_time',
        )