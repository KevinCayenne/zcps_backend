"""
自定義異常處理器，用於將 Django REST Framework 的錯誤訊息轉換為中文。

此模組提供統一的錯誤處理機制，確保所有 API 錯誤回應都使用繁體中文。
"""

from rest_framework.views import exception_handler
from rest_framework.exceptions import (
    ValidationError,
)
from rest_framework import status
from rest_framework.response import Response
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError
import logging

logger = logging.getLogger(__name__)

# 錯誤訊息對照表（英文 -> 繁體中文）
ERROR_MESSAGES = {
    # 驗證錯誤
    "This field is required.": "此欄位為必填。",
    "This field may not be blank.": "此欄位不能為空。",
    "This field may not be null.": "此欄位不能為 null。",
    "Invalid email format.": "無效的電子郵件格式。",
    "Email is required.": "電子郵件為必填。",
    "Password is required.": "密碼為必填。",
    "Code must contain only numbers.": "驗證碼只能包含數字。",
    "A user with this email already exists.": "此電子郵件已被使用。",
    "A user with this username already exists.": "此使用者名稱已被使用。",
    # 認證錯誤
    "Authentication credentials were not provided.": "未提供認證憑證。",
    "Invalid token.": "無效的令牌。",
    "Token is invalid or expired.": "令牌無效或已過期。",
    "No active account found with the given credentials.": "找不到使用此憑證的有效帳號。",
    # 權限錯誤
    "You do not have permission to perform this action.": "您沒有執行此操作的權限。",
    # 其他錯誤
    "Not found.": "找不到資源。",
    'Method "{method}" not allowed.': '不允許使用 "{method}" 方法。',
    "Could not satisfy the request Accept header.": "無法滿足請求的 Accept 標頭。",
    'Unsupported media type "{media_type}" in request.': '請求中不支援的媒體類型 "{media_type}"。',
    "Request was throttled. Expected available in {wait} second.": "請求被限制。預計 {wait} 秒後可用。",
    "Request was throttled. Expected available in {wait} seconds.": "請求被限制。預計 {wait} 秒後可用。",
}


def translate_error_message(message: str, **kwargs) -> str:
    """
    將英文錯誤訊息翻譯為繁體中文。

    Args:
        message: 原始錯誤訊息
        **kwargs: 用於格式化訊息的參數

    Returns:
        翻譯後的繁體中文錯誤訊息
    """
    # 先嘗試直接匹配
    if message in ERROR_MESSAGES:
        translated = ERROR_MESSAGES[message]
        if kwargs:
            try:
                return translated.format(**kwargs)
            except KeyError:
                return translated
        return translated

    # 嘗試匹配帶參數的訊息
    for en_msg, zh_msg in ERROR_MESSAGES.items():
        if "{" in en_msg:
            # 簡單的匹配邏輯（可以根據需要改進）
            if message.startswith(en_msg.split("{")[0]):
                try:
                    return zh_msg.format(**kwargs)
                except (KeyError, ValueError):
                    pass

    # 如果找不到對應的翻譯，返回原始訊息
    return message


def translate_validation_errors(errors):
    """
    遞迴翻譯驗證錯誤訊息。

    Args:
        errors: 錯誤字典或列表

    Returns:
        翻譯後的錯誤字典或列表
    """
    if isinstance(errors, dict):
        return {
            key: translate_validation_errors(value) for key, value in errors.items()
        }
    elif isinstance(errors, list):
        return [translate_validation_errors(error) for error in errors]
    elif isinstance(errors, str):
        return translate_error_message(errors)
    else:
        return errors


def custom_exception_handler(exc, context):
    """
    自定義異常處理器，將所有錯誤訊息轉換為繁體中文。

    Args:
        exc: 異常實例
        context: 包含請求資訊的上下文字典

    Returns:
        Response 物件，包含中文錯誤訊息
    """
    # 調用 DRF 的預設異常處理器
    response = exception_handler(exc, context)

    if response is not None:
        # 獲取原始錯誤資料
        data = response.data

        # 翻譯錯誤訊息
        if isinstance(data, dict):
            translated_data = translate_validation_errors(data)
        elif isinstance(data, list):
            translated_data = [translate_error_message(str(item)) for item in data]
        else:
            translated_data = translate_error_message(str(data))

        # 更新回應資料
        response.data = translated_data

        # 如果是 ValidationError，確保格式一致
        if isinstance(exc, ValidationError):
            # ValidationError 的資料已經是字典格式，直接使用翻譯後的資料
            pass

    # 處理 Django 的 ValidationError
    elif isinstance(exc, DjangoValidationError):
        error_dict = (
            exc.message_dict if hasattr(exc, "message_dict") else {"error": str(exc)}
        )
        translated_dict = translate_validation_errors(error_dict)
        response = Response(translated_dict, status=status.HTTP_400_BAD_REQUEST)

    # 處理資料庫完整性錯誤
    elif isinstance(exc, IntegrityError):
        error_msg = str(exc)
        # 常見的完整性錯誤訊息翻譯
        if "UNIQUE constraint" in error_msg or "duplicate key" in error_msg:
            translated_msg = "資料已存在，無法重複建立。"
        elif "FOREIGN KEY constraint" in error_msg:
            translated_msg = "關聯資料不存在。"
        else:
            translated_msg = "資料完整性錯誤，請檢查輸入資料。"
        response = Response(
            {"error": translated_msg, "detail": error_msg},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return response
