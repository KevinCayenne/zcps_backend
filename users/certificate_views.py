"""
Views for certificate template management.

Provides API endpoints for fetching certificate templates and issuing certificates from external API.
"""
import logging
import requests
from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter, OpenApiExample, inline_serializer
from django.conf import settings
from typing import Tuple, Optional, Dict, Any

logger = logging.getLogger(__name__)


def get_template(template_id: int) -> Tuple[Optional[Dict[str, Any]], int]:
    """
    從外部 API 獲取證書模板資訊。
    
    Args:
        template_id: 證書模板的 ID（整數）
        
    Returns:
        Tuple[Optional[Dict], int]: (響應數據, HTTP 狀態碼)
        - 成功時返回 (response_data, status_code)
        - 錯誤時返回 (error_dict, status_code)
        
    Raises:
        不拋出異常，所有錯誤都通過返回值處理
    """
    # 從設置中獲取外部 API 的 base URL 和 API key
    external_api_base_url = getattr(
        settings, 
        'CERTIFICATE_API_BASE_URL', 
        'https://tc-platform-service.turingcerts.com'  # 默認值，應該從環境變量配置
    )
    
    api_key = getattr(
        settings,
        'CERTIFICATE_API_KEY',
        ''
    )
    
    if not api_key:
        logger.error("CERTIFICATE_API_KEY 未配置")
        return (
            {'error': 'API key 未配置，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # 構建外部 API URL
    external_api_url = f"{external_api_base_url}/openapi/v1/templates/get-template"
    
    # 準備請求參數和標頭
    params = {'id': template_id}
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
    }
    
    try:
        # 調用外部 API
        response = requests.get(
            external_api_url,
            params=params,
            headers=headers,
            timeout=30  # 30 秒超時
        )
        
        # 記錄響應狀態
        logger.info(
            f"External API call to {external_api_url} returned status {response.status_code} "
            f"for template_id={template_id}"
        )
        
        # 處理不同的 HTTP 狀態碼
        if response.status_code == 200:
            # 成功響應，返回外部 API 的響應數據
            response_data = response.json()
            
            # 檢查業務代碼
            business_code = response_data.get('businessCode', 0)
            
            # 根據業務代碼處理不同的錯誤情況
            if business_code == 0:
                # 正常情況，返回成功響應
                return (response_data, status.HTTP_200_OK)
            elif business_code == 9999:
                # CC 帳號或模板不存在
                return (response_data, status.HTTP_404_NOT_FOUND)
            elif business_code == 9994:
                # 此帳號不擁有指定的模板
                return (response_data, status.HTTP_403_FORBIDDEN)
            elif business_code in [9599, 9596, 9597]:
                # 其他業務錯誤（版本不支援、無權限、找不到模板）
                return (response_data, status.HTTP_403_FORBIDDEN)
            else:
                # 未知的業務代碼，返回原始響應
                return (response_data, status.HTTP_200_OK)
        
        elif response.status_code == 403:
            # 外部 API 返回 403，表示沒有權限
            try:
                response_data = response.json()
                return (response_data, status.HTTP_403_FORBIDDEN)
            except ValueError:
                return (
                    {'error': '此帳號不擁有指定的模板或沒有讀取權限'},
                    status.HTTP_403_FORBIDDEN
                )
        
        elif response.status_code == 404:
            # 外部 API 返回 404，表示找不到資源
            try:
                response_data = response.json()
                return (response_data, status.HTTP_404_NOT_FOUND)
            except ValueError:
                return (
                    {'error': 'CC 帳號或模板不存在'},
                    status.HTTP_404_NOT_FOUND
                )
        
        else:
            # 其他 HTTP 錯誤
            logger.error(
                f"External API returned unexpected status {response.status_code}: {response.text}"
            )
            return (
                {
                    'error': f'外部 API 返回錯誤狀態碼: {response.status_code}',
                    'details': response.text[:500]  # 限制錯誤詳情長度
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    except requests.exceptions.Timeout:
        logger.error(f"Timeout when calling external API for template_id={template_id}")
        return (
            {'error': '外部 API 請求超時，請稍後再試'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error when calling external API for template_id={template_id}")
        return (
            {'error': '無法連接到外部 API，請檢查網路連接'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception when calling external API: {str(e)}")
        return (
            {'error': f'外部 API 請求失敗: {str(e)}'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except ValueError as e:
        # JSON 解析錯誤
        logger.error(f"JSON decode error: {str(e)}")
        return (
            {'error': '外部 API 返回的響應格式無效'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except Exception as e:
        # 其他未預期的錯誤
        logger.error(f"Unexpected error when calling external API: {str(e)}", exc_info=True)
        return (
            {'error': '發生未預期的錯誤，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class GetTemplateView(APIView):
    """
    API endpoint to fetch certificate template information from external API.
    
    GET /api/certificates/templates/get-template/
    Accepts template_id as query parameter. API key is configured on the backend.
    """
    
    permission_classes = [AllowAny]
    
    @extend_schema(
        tags=['Certificates'],
        summary='Get certificate template by ID',
        description="""
        使用模板 ID 從外部 API 獲取指定的證書模板資訊。
        
        **流程說明：**
        1. 接收 template_id 參數
        2. 使用後端配置的 API key 調用外部 API `/openapi/v1/templates/get-template`
        3. 返回模板資訊或錯誤訊息
        
        **業務代碼說明：**
        - 0: 正常
        - 9999: CC 帳號或模板不存在
        - 9994: 此帳號不擁有指定的模板
        - 9599: 不支援的模板版本
        - 9596: CC 帳號沒有權限訪問此模板
        - 9597: 找不到模板
        
        **注意事項：**
        - API key 已在後端配置，無需前端傳遞
        - template_id 必須是有效的整數
        """,
        parameters=[
            OpenApiParameter(
                name='template_id',
                type=int,
                location=OpenApiParameter.QUERY,
                required=True,
                description='證書模板的 ID',
            ),
        ],
        examples=[
            OpenApiExample(
                'Success Response',
                value={
                    "success": True,
                    "code": 0,
                    "businessCode": 0,
                    "message": {
                        "executionTime": "2025-12-01T11:55:32.759Z",
                        "message": "string"
                    },
                    "content": {
                        "id": 0,
                        "name": "string",
                        "shareId": "string",
                        "category": "award",
                        "language": "english",
                        "content": "string",
                        "metadata": {},
                        "backgroundImageId": "string",
                        "landscape": True,
                        "keyList": [
                            {
                                "uid": "string",
                                "key": "string",
                                "type": "text:string",
                                "description": "string",
                                "renderValue": "string"
                            }
                        ],
                        "createTime": "string",
                        "updateTime": {},
                        "version": 0,
                        "isDiwTemplate": True
                    }
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='成功獲取模板資訊',
                response=inline_serializer(
                    name='TemplateSuccessResponse',
                    fields={
                        'success': serializers.BooleanField(help_text='請求是否成功'),
                        'code': serializers.IntegerField(help_text='HTTP 狀態碼'),
                        'businessCode': serializers.IntegerField(help_text='業務代碼 (0=正常)'),
                        'message': serializers.DictField(help_text='訊息物件'),
                        'content': serializers.DictField(help_text='模板內容'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad Request - 缺少必要參數',
                response=inline_serializer(
                    name='TemplateBadRequestResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
            403: OpenApiResponse(
                description='Forbidden - 此帳號不擁有指定的模板或沒有讀取權限',
                response=inline_serializer(
                    name='TemplateForbiddenResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            404: OpenApiResponse(
                description='Not Found - CC 帳號或模板不存在',
                response=inline_serializer(
                    name='TemplateNotFoundResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            500: OpenApiResponse(
                description='Internal Server Error - 外部 API 調用失敗',
                response=inline_serializer(
                    name='TemplateServerErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
        }
    )
    def get(self, request):
        """
        獲取證書模板資訊。
        
        Args:
            request: HTTP 請求物件，包含 template_id 和 api_token 查詢參數
            
        Returns:
            Response: 包含模板資訊的響應，或錯誤訊息
        """
        # 獲取查詢參數
        template_id = request.query_params.get('template_id')
        
        # 驗證必要參數
        if not template_id:
            return Response(
                {'error': 'template_id 參數是必需的'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 驗證 template_id 是否為整數
        try:
            template_id = int(template_id)
        except ValueError:
            return Response(
                {'error': 'template_id 必須是有效的整數'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 調用 get_template 函數獲取模板資訊
        response_data, status_code = get_template(template_id)
        return Response(response_data, status=status_code)


def issue_certificates_to_new_group(request_data: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int]:
    """
    發證到新的證書群組。
    
    Args:
        request_data: 發證請求的數據
        
    Returns:
        Tuple[Optional[Dict], int]: (響應數據, HTTP 狀態碼)
        - 成功時返回 (response_data, status_code)
        - 錯誤時返回 (error_dict, status_code)
    """
    # 從設置中獲取外部 API 的 base URL 和 API key
    external_api_base_url = getattr(
        settings, 
        'CERTIFICATE_API_BASE_URL', 
        'https://tc-platform-service.turingcerts.com'
    )
    
    api_key = getattr(
        settings,
        'CERTIFICATE_API_KEY',
        ''
    )
    
    if not api_key:
        logger.error("CERTIFICATE_API_KEY 未配置")
        return (
            {'error': 'API key 未配置，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # 構建外部 API URL
    external_api_url = f"{external_api_base_url}/openapi/v1/cert-record-groups/issue-certificates-to-new-group"
    
    # 準備請求標頭
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
    }
    
    try:
        # 調用外部 API
        response = requests.post(
            external_api_url,
            json=request_data,
            headers=headers,
            timeout=60  # 發證可能需要更長時間
        )
        
        # 記錄響應狀態
        logger.info(
            f"External API call to {external_api_url} returned status {response.status_code}"
        )
        
        # 處理不同的 HTTP 狀態碼
        if response.status_code in [200, 201]:  # 200 或 201 都表示成功
            response_data = response.json()
            business_code = response_data.get('businessCode', 0)
            
            if business_code == 0:
                # 成功創建新群組並開始發證
                return (response_data, status.HTTP_200_OK)
            else:
                # 其他業務錯誤，根據業務代碼返回對應狀態碼
                return (response_data, status.HTTP_200_OK)
        
        elif response.status_code == 400:
            # 發證資料有誤
            try:
                response_data = response.json()
                return (response_data, status.HTTP_400_BAD_REQUEST)
            except ValueError:
                return (
                    {'error': '發證資料有誤'},
                    status.HTTP_400_BAD_REQUEST
                )
        
        elif response.status_code == 403:
            # 權限相關錯誤
            try:
                response_data = response.json()
                business_code = response_data.get('businessCode', 0)
                # 業務代碼: 9695, 9698, 9684, 9677
                return (response_data, status.HTTP_403_FORBIDDEN)
            except ValueError:
                return (
                    {'error': '沒有權限執行此操作'},
                    status.HTTP_403_FORBIDDEN
                )
        
        elif response.status_code == 404:
            # 資源不存在
            try:
                response_data = response.json()
                return (response_data, status.HTTP_404_NOT_FOUND)
            except ValueError:
                return (
                    {'error': '指定的 CC 帳號/CSV 檔案/證書模板不存在'},
                    status.HTTP_404_NOT_FOUND
                )
        
        else:
            # 其他 HTTP 錯誤
            logger.error(
                f"External API returned unexpected status {response.status_code}: {response.text}"
            )
            return (
                {
                    'error': f'外部 API 返回錯誤狀態碼: {response.status_code}',
                    'details': response.text[:500]
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    except requests.exceptions.Timeout:
        logger.error("Timeout when calling external API for issue certificates to new group")
        return (
            {'error': '外部 API 請求超時，請稍後再試'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.ConnectionError:
        logger.error("Connection error when calling external API for issue certificates to new group")
        return (
            {'error': '無法連接到外部 API，請檢查網路連接'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception when calling external API: {str(e)}")
        return (
            {'error': f'外部 API 請求失敗: {str(e)}'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except ValueError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return (
            {'error': '外部 API 返回的響應格式無效'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except Exception as e:
        logger.error(f"Unexpected error when calling external API: {str(e)}", exc_info=True)
        return (
            {'error': '發生未預期的錯誤，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def issue_certificates_to_existing_group(request_data: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int]:
    """
    發證到現有的證書群組。
    
    Args:
        request_data: 發證請求的數據
        
    Returns:
        Tuple[Optional[Dict], int]: (響應數據, HTTP 狀態碼)
        - 成功時返回 (response_data, status_code)
        - 錯誤時返回 (error_dict, status_code)
    """
    # 從設置中獲取外部 API 的 base URL 和 API key
    external_api_base_url = getattr(
        settings, 
        'CERTIFICATE_API_BASE_URL', 
        'https://tc-platform-service.turingcerts.com'
    )
    
    api_key = getattr(
        settings,
        'CERTIFICATE_API_KEY',
        ''
    )
    
    if not api_key:
        logger.error("CERTIFICATE_API_KEY 未配置")
        return (
            {'error': 'API key 未配置，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # 構建外部 API URL
    external_api_url = f"{external_api_base_url}/openapi/v1/cert-record-groups/issue-certificates-to-existing-group"
    
    # 準備請求標頭
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
    }

    print(request_data)
    # return (request_data, status.HTTP_200_OK)
    
    try:
        # 調用外部 API
        response = requests.post(
            external_api_url,
            json=request_data,
            headers=headers,
            timeout=60  # 發證可能需要更長時間
        )
        
        # 記錄響應狀態
        logger.info(
            f"External API call to {external_api_url} returned status {response.status_code}"
        )
        
        # 處理不同的 HTTP 狀態碼
        if response.status_code in [200, 201]:  # 200 或 201 都表示成功
            response_data = response.json()
            business_code = response_data.get('businessCode', 0)
            
            if business_code == 0:
                # 成功開始發證流程
                return (response_data, status.HTTP_200_OK)
            else:
                # 其他業務錯誤
                return (response_data, status.HTTP_200_OK)
        
        elif response.status_code == 400:
            # 發證資料有誤
            try:
                response_data = response.json()
                return (response_data, status.HTTP_400_BAD_REQUEST)
            except ValueError:
                return (
                    {'error': '發證資料有誤'},
                    status.HTTP_400_BAD_REQUEST
                )
        
        elif response.status_code == 403:
            # 權限相關錯誤
            try:
                response_data = response.json()
                business_code = response_data.get('businessCode', 0)
                # 業務代碼: 9695, 9994, 9699, 9698, 9684, 9677
                return (response_data, status.HTTP_403_FORBIDDEN)
            except ValueError:
                return (
                    {'error': '沒有權限執行此操作'},
                    status.HTTP_403_FORBIDDEN
                )
        
        elif response.status_code == 404:
            # 資源不存在
            try:
                response_data = response.json()
                return (response_data, status.HTTP_404_NOT_FOUND)
            except ValueError:
                return (
                    {'error': '指定的 CC 帳號/CSV 檔案/證書群組不存在'},
                    status.HTTP_404_NOT_FOUND
                )
        
        else:
            # 其他 HTTP 錯誤
            logger.error(
                f"External API returned unexpected status {response.status_code}: {response.text}"
            )
            return (
                {
                    'error': f'外部 API 返回錯誤狀態碼: {response.status_code}',
                    'details': response.text[:500]
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    except requests.exceptions.Timeout:
        logger.error("Timeout when calling external API for issue certificates to existing group")
        return (
            {'error': '外部 API 請求超時，請稍後再試'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.ConnectionError:
        logger.error("Connection error when calling external API for issue certificates to existing group")
        return (
            {'error': '無法連接到外部 API，請檢查網路連接'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception when calling external API: {str(e)}")
        return (
            {'error': f'外部 API 請求失敗: {str(e)}'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except ValueError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return (
            {'error': '外部 API 返回的響應格式無效'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except Exception as e:
        logger.error(f"Unexpected error when calling external API: {str(e)}", exc_info=True)
        return (
            {'error': '發生未預期的錯誤，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class IssueCertificatesToNewGroupView(APIView):
    """
    API endpoint to issue certificates to a new certificate group.
    
    POST /api/certificates/issue-to-new-group/
    Accepts request body. API key is configured on the backend.
    """
    
    permission_classes = [AllowAny]
    
    @extend_schema(
        tags=['Certificates'],
        summary='Issue certificates to new group',
        description="""
        發證到新的證書群組。
        
        **流程說明：**
        1. 接收發證資料
        2. 使用後端配置的 API key 調用外部 API `/openapi/v1/cert-record-groups/issue-certificates-to-new-group`
        3. 返回證書群組 ID 或錯誤訊息
        
        **業務代碼說明：**
        - 0: 成功創建新群組並開始發證
        - 9999: 指定的 CC 帳號/CSV 檔案不存在
        - 9994: 此帳號不擁有此 CSV 檔案
        - 9695: 發證密鑰錯誤
        - 9698: 目標 CC 帳號無權設定證書到期日
        - 9684: 目標 CC 帳號無權發送證書到手機號碼
        - 9697: 證書到期日格式錯誤，應為數字
        - 9696: 證書到期日錯誤，應為未來日期
        - 9693: 證書資料中的電子郵件格式錯誤
        - 9692: 證書資料中的 Uuid 格式錯誤
        - 9597: 找不到模板
        - 9596: CC 帳號沒有權限訪問此模板
        - 9599: 模板版本過舊，無法發證
        - 9598: 發證密鑰與模板密鑰不匹配
        - 9677: 目標 CC 帳號配額不足
        
        **注意事項：**
        - API key 已在後端配置，無需前端傳遞
        - 需要在請求體中提供完整的發證資料
        - certPassword（發證密鑰）是必填欄位
        - certsData 中每個對象必須包含 email 欄位（必填）
        - certsData 中只應包含 tx- 開頭的模板欄位，不要包含 i- 或 lg- 開頭的欄位
        - autoNotificationTime 如果提供，必須是 ISO 8601 格式的日期字串
        """,
        parameters=[],
        request=inline_serializer(
            name='IssueCertificatesRequest',
            fields={
                'isDownloadButtonEnabled': serializers.BooleanField(required=False, help_text='是否啟用下載按鈕'),
                'customEmail': serializers.DictField(required=False, help_text='自訂電子郵件設定'),
                'certPassword': serializers.CharField(required=True, help_text='發證密鑰（必填）'),
                'certRecordRemark': serializers.CharField(required=False, help_text='證書備註'),
                'skipSendingNotification': serializers.BooleanField(required=False, help_text='跳過發送通知'),
                'setVisibilityPublic': serializers.BooleanField(required=False, help_text='設定為公開'),
                'certsData': serializers.ListField(
                    required=True, 
                    help_text='證書資料列表。每個對象必須包含 email 欄位（必填），且只應包含 tx- 開頭的模板欄位'
                ),
                'pdfProtectionPassword': serializers.CharField(required=False, help_text='PDF 保護密碼'),
                'autoNotificationTime': serializers.CharField(required=False, help_text='自動通知時間（ISO 8601 格式，如：2025-12-01T12:00:00Z）'),
                'name': serializers.CharField(required=False, help_text='群組名稱'),
                'templateId': serializers.IntegerField(required=True, help_text='模板 ID'),
            }
        ),
        examples=[
            OpenApiExample(
                'Request Example',
                value={
                    "isDownloadButtonEnabled": True,
                    "customEmail": {
                        "subject": "證書發放通知",
                        "description": "您的證書已準備就緒",
                        "contactEmail": "contact@example.com"
                    },
                    "certPassword": "password123",
                    "certRecordRemark": "備註",
                    "skipSendingNotification": False,
                    "setVisibilityPublic": True,
                    "certsData": [{}],
                    "pdfProtectionPassword": "",
                    "autoNotificationTime": "2025-12-01",
                    "name": "證書群組名稱",
                    "templateId": 123
                },
                request_only=True,
            ),
            OpenApiExample(
                'Success Response',
                value={
                    "success": True,
                    "code": 0,
                    "businessCode": 0,
                    "message": {
                        "executionTime": "2025-12-01T12:04:45.101Z",
                        "message": "string"
                    },
                    "content": {
                        "id": 0
                    }
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='成功創建新群組並開始發證',
                response=inline_serializer(
                    name='IssueCertificatesSuccessResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                        'content': serializers.DictField(help_text='包含證書群組 ID'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad Request - 發證資料有誤',
                response=inline_serializer(
                    name='IssueCertificatesBadRequestResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
            403: OpenApiResponse(
                description='Forbidden - 權限不足或配額不足',
                response=inline_serializer(
                    name='IssueCertificatesForbiddenResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            404: OpenApiResponse(
                description='Not Found - 指定的資源不存在',
                response=inline_serializer(
                    name='IssueCertificatesNotFoundResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            500: OpenApiResponse(
                description='Internal Server Error - 外部 API 調用失敗',
                response=inline_serializer(
                    name='IssueCertificatesServerErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
        }
    )
    def post(self, request):
        """
        發證到新的證書群組。
        
        Args:
            request: HTTP 請求物件，包含 api_token 查詢參數和發證資料
            
        Returns:
            Response: 包含證書群組 ID 的響應，或錯誤訊息
        """
        # 獲取請求體數據
        request_data = request.data
        
        # 調用 issue_certificates_to_new_group 函數
        response_data, status_code = issue_certificates_to_new_group(request_data)
        return Response(response_data, status=status_code)


class IssueCertificatesToExistingGroupView(APIView):
    """
    API endpoint to issue certificates to an existing certificate group.
    
    POST /api/certificates/issue-to-existing-group/
    Accepts request body. API key is configured on the backend.
    """
    
    permission_classes = [AllowAny]
    
    @extend_schema(
        tags=['Certificates'],
        summary='Issue certificates to existing group',
        description="""
        發證到現有的證書群組。
        
        **流程說明：**
        1. 接收 api_token 參數和發證資料
        2. 調用外部 API `/openapi/v1/cert-record-groups/issue-certificates-to-existing-group`
        3. 返回發證結果或錯誤訊息
        
        **業務代碼說明：**
        - 0: 成功開始發證流程
        - 9999: 指定的 CC 帳號/CSV 檔案/證書模板不存在
        - 9994: 此帳號不擁有指定的 CSV 檔案或證書群組
        - 9695: 發證密鑰錯誤
        - 9699: 狀態為「發證中」，無法發證
        - 9698: 目標 CC 帳號無權設定證書到期日
        - 9684: 目標 CC 帳號無權發送證書到手機號碼
        - 9697: 證書到期日格式錯誤，應為數字
        - 9696: 證書到期日錯誤，應為未來日期
        - 9693: 證書資料中的電子郵件格式錯誤
        - 9692: 證書資料中的 Uuid 格式錯誤
        - 9599: 模板版本過舊，無法發證
        - 9598: 發證密鑰與模板密鑰不匹配
        - 9677: 目標 CC 帳號配額不足
        
        **注意事項：**
        - 需要提供有效的 api_token 用於外部 API 認證
        - 需要在請求體中提供完整的發證資料，包括 certRecordGroupId
        - certPassword（發證密鑰）是必填欄位
        - certsData 中每個對象必須包含 email 欄位（必填）
        - certsData 中只應包含 tx- 開頭的模板欄位，不要包含 i- 或 lg- 開頭的欄位
        - autoNotificationTime 如果提供，必須是 ISO 8601 格式的日期字串
        """,
        parameters=[
            OpenApiParameter(
                name='api_token',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='用於外部 API 認證的 token',
            ),
        ],
        request=inline_serializer(
            name='IssueCertificatesToExistingGroupRequest',
            fields={
                'isDownloadButtonEnabled': serializers.BooleanField(required=False, help_text='是否啟用下載按鈕'),
                'customEmail': serializers.DictField(required=False, help_text='自訂電子郵件設定'),
                'certPassword': serializers.CharField(required=True, help_text='發證密鑰（必填）'),
                'certRecordRemark': serializers.CharField(required=False, help_text='證書備註'),
                'skipSendingNotification': serializers.BooleanField(required=False, help_text='跳過發送通知'),
                'setVisibilityPublic': serializers.BooleanField(required=False, help_text='設定為公開'),
                'certsData': serializers.ListField(
                    required=True, 
                    help_text='證書資料列表。每個對象必須包含 email 欄位（必填），且只應包含 tx- 開頭的模板欄位'
                ),
                'pdfProtectionPassword': serializers.CharField(required=False, help_text='PDF 保護密碼'),
                'autoNotificationTime': serializers.CharField(required=False, help_text='自動通知時間（ISO 8601 格式，如：2025-12-01T12:00:00Z）'),
                'certRecordGroupId': serializers.IntegerField(required=True, help_text='證書群組 ID'),
            }
        ),
        examples=[
            OpenApiExample(
                'Request Example',
                value={
                    "isDownloadButtonEnabled": True,
                    "customEmail": {
                        "subject": "證書發放通知",
                        "description": "您的證書已準備就緒",
                        "contactEmail": "contact@example.com"
                    },
                    "certPassword": "password123",
                    "certRecordRemark": "備註",
                    "skipSendingNotification": False,
                    "setVisibilityPublic": True,
                    "certsData": [{}],
                    "pdfProtectionPassword": "",
                    "autoNotificationTime": "2025-12-01",
                    "certRecordGroupId": 456
                },
                request_only=True,
            ),
            OpenApiExample(
                'Success Response',
                value={
                    "success": True,
                    "code": 0,
                    "businessCode": 0,
                    "message": {
                        "executionTime": "2025-12-01T12:04:45.104Z",
                        "message": "string"
                    },
                    "content": {}
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='成功開始發證流程',
                response=inline_serializer(
                    name='IssueCertificatesToExistingGroupSuccessResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                        'content': serializers.DictField(),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad Request - 發證資料有誤',
                response=inline_serializer(
                    name='IssueCertificatesToExistingGroupBadRequestResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
            403: OpenApiResponse(
                description='Forbidden - 權限不足、配額不足或狀態不允許',
                response=inline_serializer(
                    name='IssueCertificatesToExistingGroupForbiddenResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            404: OpenApiResponse(
                description='Not Found - 指定的資源不存在',
                response=inline_serializer(
                    name='IssueCertificatesToExistingGroupNotFoundResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            500: OpenApiResponse(
                description='Internal Server Error - 外部 API 調用失敗',
                response=inline_serializer(
                    name='IssueCertificatesToExistingGroupServerErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
        }
    )
    def post(self, request):
        """
        發證到現有的證書群組。
        
        Args:
            request: HTTP 請求物件，包含 api_token 查詢參數和發證資料
            
        Returns:
            Response: 包含發證結果的響應，或錯誤訊息
        """
        # 獲取請求體數據
        request_data = request.data
        
        # 調用 issue_certificates_to_existing_group 函數
        response_data, status_code = issue_certificates_to_existing_group(request_data)
        return Response(response_data, status=status_code)


def build_certs_data_from_template(template_data: Dict[str, Any], user_data: Dict[str, Any] = None, certificate_application=None) -> list:
    """
    根據模板資訊和用戶提供的資料構建 certsData，自動帶入會員資料、就診醫院、醫師、日期和認證序號。
    
    Args:
        template_data: 模板資訊（從 get_template 獲取）
        user_data: 用戶提供的證書資料（包含 email 和對應模板欄位的值，可選）
        certificate_application: CertificateApplication 實例（可選，如果提供則自動帶入相關資料）
        
    Returns:
        certsData 列表
    """
    key_list = template_data.get('content', {}).get('keyList', [])
    
    # 如果提供了 certificate_application，自動帶入相關資料
    if certificate_application:
        user = certificate_application.user
        clinic = certificate_application.clinic
        
        # 自動帶入會員姓名（組合 first_name 和 last_name）
        member_name = ""
        if user.first_name or user.last_name:
            member_name = f"{user.first_name or ''}{user.last_name or ''}".strip()
        elif user.username:
            member_name = user.username
        else:
            member_name = user.email.split('@')[0] if user.email else "會員"
        
        # 自動帶入就診醫院
        hospital_name = clinic.name if clinic else ""
        
        # 自動帶入手術執行醫師
        # 優先從 certificate_application.surgeon_name 獲取，如果為空則從 certificate_data 中獲取
        surgeon_name = certificate_application.surgeon_name or ""
        if not surgeon_name and certificate_application.certificate_data:
            surgeon_name = certificate_application.certificate_data.get('tx-103', '') or certificate_application.certificate_data.get('surgeon_name', '')
        
        # 自動帶入手術執行日期
        # 優先從 certificate_application.surgery_date 獲取，如果為空則從 certificate_data 中獲取
        surgery_date = ""
        if certificate_application.surgery_date:
            surgery_date = certificate_application.surgery_date.strftime('%Y-%m-%d')
        elif certificate_application.certificate_data:
            # 嘗試從 certificate_data 中獲取日期
            date_value = certificate_application.certificate_data.get('tx-104', '') or certificate_application.certificate_data.get('surgery_date', '')
            if date_value:
                # 如果已經是字符串格式，直接使用；如果是日期對象，需要格式化
                if isinstance(date_value, str):
                    surgery_date = date_value
                else:
                    # 嘗試解析為日期
                    try:
                        from datetime import datetime
                        if isinstance(date_value, datetime):
                            surgery_date = date_value.strftime('%Y-%m-%d')
                    except:
                        surgery_date = str(date_value)
        
        # 生成或獲取認證序號
        if not certificate_application.certificate_number:
            certificate_application.certificate_number = certificate_application.generate_certificate_number()
            certificate_application.save(update_fields=['certificate_number'])
        cert_number = certificate_application.certificate_number
        
        # 構建證書資料，優先使用用戶提供的資料，否則使用自動帶入的資料
        cert_data = {
            'email': user_data.get('email') if user_data else user.email or 'example@example.com'
        }
    else:
        # 沒有提供 certificate_application，使用用戶提供的資料或默認值
        cert_data = {
            'email': user_data.get('email', 'example@example.com') if user_data else 'example@example.com'
        }
        member_name = ""
        hospital_name = ""
        surgeon_name = ""
        surgery_date = ""
        cert_number = ""
    
    # 根據模板的 keyList 填入用戶提供的資料或自動帶入的資料
    for key_item in key_list:
        key = key_item.get('key')
        
        # 只保留 tx- 開頭的欄位
        if not key or not key.startswith('tx-'):
            continue
        
        # 優先順序：用戶提供的值（非空） > certificate_data 中的值（非空） > 根據 key 自動填充 > 空值
        user_value = user_data.get(key) if user_data else None
        cert_data_value = None
        if certificate_application and certificate_application.certificate_data:
            cert_data_value = certificate_application.certificate_data.get(key)
        
        # 如果用戶提供了非空值，使用用戶的值
        if user_value and str(user_value).strip():
            cert_data[key] = user_value
        # 如果 certificate_data 中有非空值，使用 certificate_data 中的值
        elif cert_data_value and str(cert_data_value).strip():
            cert_data[key] = cert_data_value
        # 否則根據 key 自動填充
        elif certificate_application:
            # 根據特定的 key 自動填充對應的資料
            if key == 'tx-101':
                # tx-101: 姓名
                cert_data[key] = member_name
            elif key == 'tx-102':
                # tx-102: 就診醫院
                cert_data[key] = hospital_name
            elif key == 'tx-103':
                # tx-103: 手術執行醫師
                cert_data[key] = surgeon_name
            elif key == 'tx-104':
                # tx-104: 手術執行日期
                cert_data[key] = surgery_date if surgery_date else ""
            elif key == 'tx-105':
                # tx-105: 認證序號
                cert_data[key] = cert_number
            else:
                # 其他欄位設置為空字符串，讓用戶自己填寫
                key_type = key_item.get('type', '')
                if 'number' in key_type or 'integer' in key_type:
                    cert_data[key] = None  # 數字類型使用 None
                elif 'date' in key_type:
                    cert_data[key] = ""  # 日期類型使用空字符串
                else:
                    cert_data[key] = ""  # 其他類型使用空字符串
        else:
            # 沒有提供 certificate_application，設置為空字符串
            key_type = key_item.get('type', '')
            if 'number' in key_type or 'integer' in key_type:
                cert_data[key] = None  # 數字類型使用 None
            elif 'date' in key_type:
                cert_data[key] = ""  # 日期類型使用空字符串
            else:
                cert_data[key] = ""  # 其他類型使用空字符串
    
    return [cert_data]


class IssueCertificatesWithTemplateView(APIView):
    """
    API endpoint to issue certificates with automatic template fetching.
    
    POST /api/certificates/issue-with-template/
    This endpoint combines template fetching and certificate issuance into one call.
    """
    
    permission_classes = [AllowAny]
    
    @extend_schema(
        tags=['Certificates'],
        summary='Issue certificates with template (Combined API)',
        description="""
        發證並自動獲取模板資訊（合併 API）。
        
        **流程說明：**
        1. 使用後端配置的 templateId 自動調用外部 API 獲取模板資訊
        2. 根據模板的 keyList 自動構建 certsData
        3. 調用外部 API 發證到新群組
        4. 返回證書群組 ID
        
        **優點：**
        - 前端只需要調用一個 API 即可完成發證
        - 自動處理模板資訊和 certsData 構建
        - 簡化前端邏輯
        - API key 和 templateId 都在後端配置，更安全
        
        **業務代碼說明：**
        - 0: 成功創建新群組並開始發證
        - 其他業務代碼與發證 API 相同
        
        **注意事項：**
        - API key、templateId 和 certPassword 已在後端配置，無需前端傳遞
        - 需要提供驗證 token（從驗證 email 中獲取）
        - 只需要提供證書資料（certificateData），必須包含 email 欄位
        - 可以選擇性提供其他證書欄位，未提供的欄位會使用默認值
        """,
        parameters=[],
        request=inline_serializer(
            name='IssueCertificatesWithTemplateRequest',
            fields={
                'token': serializers.CharField(required=True, help_text='驗證 token（從驗證 email 中獲取）'),
                'name': serializers.CharField(required=False, help_text='群組名稱'),
                'isDownloadButtonEnabled': serializers.BooleanField(required=False, help_text='是否啟用下載按鈕'),
                'skipSendingNotification': serializers.BooleanField(required=False, help_text='跳過發送通知'),
                'setVisibilityPublic': serializers.BooleanField(required=False, help_text='設定為公開'),
                'certRecordRemark': serializers.CharField(required=False, help_text='證書備註'),
                'pdfProtectionPassword': serializers.CharField(required=False, help_text='PDF 保護密碼'),
                'autoNotificationTime': serializers.CharField(required=False, help_text='自動通知時間（ISO 8601 格式）'),
                'customEmail': serializers.DictField(required=False, help_text='自訂電子郵件設定'),
                'certificateData': serializers.DictField(
                    required=False,
                    help_text='證書資料。必須包含 email 欄位，可選包含 tx- 開頭的模板欄位值。未提供的欄位會使用默認值。如果未提供，將使用申請時提交的資料。'
                ),
            }
        ),
        examples=[
            OpenApiExample(
                'Request Example',
                value={
                    "token": "your_verification_token_here",
                    "name": "證書群組名稱",
                    "isDownloadButtonEnabled": True,
                    "skipSendingNotification": False,
                    "setVisibilityPublic": True,
                    "certRecordRemark": "備註",
                    "certificateData": {
                        "email": "user@example.com",
                        "tx-101": "獎狀名稱",
                        "tx-103": "張三"
                    }
                },
                request_only=True,
            ),
            OpenApiExample(
                'Success Response',
                value={
                    "success": True,
                    "code": 0,
                    "businessCode": 0,
                    "message": {
                        "executionTime": "2025-12-01T12:04:45.101Z",
                        "message": "Successfully built a new certificate group and started the process of producing certificates."
                    },
                    "content": {
                        "id": 13107
                    }
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='成功創建新群組並開始發證',
                response=inline_serializer(
                    name='IssueCertificatesWithTemplateSuccessResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                        'content': serializers.DictField(help_text='包含證書群組 ID'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad Request - 缺少必要參數或發證資料有誤',
                response=inline_serializer(
                    name='IssueCertificatesWithTemplateBadRequestResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
            403: OpenApiResponse(
                description='Forbidden - 權限不足或配額不足',
                response=inline_serializer(
                    name='IssueCertificatesWithTemplateForbiddenResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            404: OpenApiResponse(
                description='Not Found - 模板不存在或指定的資源不存在',
                response=inline_serializer(
                    name='IssueCertificatesWithTemplateNotFoundResponse',
                    fields={
                        'success': serializers.BooleanField(),
                        'code': serializers.IntegerField(),
                        'businessCode': serializers.IntegerField(),
                        'message': serializers.DictField(),
                    }
                )
            ),
            500: OpenApiResponse(
                description='Internal Server Error - 外部 API 調用失敗',
                response=inline_serializer(
                    name='IssueCertificatesWithTemplateServerErrorResponse',
                    fields={
                        'error': serializers.CharField(help_text='錯誤訊息')
                    }
                )
            ),
        }
    )
    def post(self, request):
        """
        發證並自動獲取模板資訊。
        
        Args:
            request: HTTP 請求物件，包含發證資料
            
        Returns:
            Response: 包含證書群組 ID 的響應，或錯誤訊息
        """
        # 從設置中獲取 templateId 和 certPassword
        template_id = getattr(settings, 'CERTIFICATE_TEMPLATE_ID', None)
        cert_password = getattr(settings, 'CERTIFICATE_PASSWORD', None)
        
        if not template_id:
            return Response(
                {'error': 'CERTIFICATE_TEMPLATE_ID 未配置，請聯繫管理員'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        if not cert_password:
            return Response(
                {'error': 'CERTIFICATE_PASSWORD 未配置，請聯繫管理員'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # 獲取請求體數據
        request_data = request.data
        
        # 驗證 token
        token = request_data.get('token')
        if not token:
            return Response(
                {'error': '缺少驗證 token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 導入 CertificateApplication（延遲導入避免循環依賴）
        from clinic.models import CertificateApplication
        from clinic.enums import CertificateApplicationStatus
        
        try:
            application = CertificateApplication.objects.select_related('user', 'clinic').get(
                verification_token=token
            )
        except CertificateApplication.DoesNotExist:
            return Response(
                {'error': '無效的驗證 token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 檢查 token 是否有效
        if not application.is_token_valid():
            return Response(
                {'error': 'Token 已過期或已被使用'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 檢查申請狀態（應該是 verified 或 pending）
        if application.status not in [CertificateApplicationStatus.VERIFIED, CertificateApplicationStatus.PENDING]:
            return Response(
                {'error': f'申請狀態不正確，當前狀態：{application.get_status_display()}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 如果還是 pending，標記為 verified
        if application.status == CertificateApplicationStatus.PENDING:
            application.mark_as_verified()
        
        # 步驟 1: 獲取模板資訊
        template_data, template_status = get_template(template_id)
        
        if template_status != status.HTTP_200_OK or not template_data:
            # 如果獲取模板失敗，返回錯誤
            if template_data:
                return Response(template_data, status=template_status)
            else:
                return Response(
                    {'error': '無法獲取模板資訊'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # 檢查業務代碼
        business_code = template_data.get('businessCode', -1)
        if business_code != 0:
            return Response(template_data, status=template_status)
        
        # 步驟 2: 構建 certsData
        # 優先使用請求中的 certificateData，如果沒有則使用申請時提交的資料
        user_certificate_data = request_data.get('certificateData', application.certificate_data)
        # 傳入 application 以自動帶入會員資料、就診醫院、醫師、日期和認證序號
        certs_data = build_certs_data_from_template(template_data, user_certificate_data, certificate_application=application)
        
        # 步驟 3: 構建發證請求數據
        from datetime import datetime, timezone
        
        issue_request_data = {
            'templateId': template_id,
            'name': request_data.get('name', f'證書群組_{template_id}'),
            'certsData': certs_data,
            'certPassword': cert_password,
            'isDownloadButtonEnabled': request_data.get('isDownloadButtonEnabled', True),
            'skipSendingNotification': request_data.get('skipSendingNotification', False),
            'setVisibilityPublic': request_data.get('setVisibilityPublic', True),
            'certRecordRemark': request_data.get('certRecordRemark', ''),
            'pdfProtectionPassword': request_data.get('pdfProtectionPassword', ''),
        }
        
        # 處理 autoNotificationTime
        if 'autoNotificationTime' in request_data:
            issue_request_data['autoNotificationTime'] = request_data['autoNotificationTime']
        else:
            # 如果沒有提供，使用當前時間
            issue_request_data['autoNotificationTime'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # 處理 customEmail
        if 'customEmail' in request_data:
            issue_request_data['customEmail'] = request_data['customEmail']
        
        # 步驟 4: 發證到新群組
        response_data, status_code = issue_certificates_to_new_group(issue_request_data)
        
        if status_code not in [status.HTTP_200_OK, status.HTTP_201_CREATED]:
            return Response(response_data, status=status_code)
        
        # 更新申請狀態為已發證
        certificate_group_id = response_data.get('content', {}).get('id')
        if certificate_group_id:
            try:
                application.mark_as_issued(certificate_group_id)
                logger.info(
                    f"Certificate application {application.id} marked as issued "
                    f"with group ID {certificate_group_id}"
                )
            except Exception as e:
                logger.error(
                    f"Failed to mark application {application.id} as issued: {e}",
                    exc_info=True
                )
                # 即使更新狀態失敗，也返回成功（證書已經發放）
        
        return Response(response_data, status=status_code)


def get_certificate(cert_id: Optional[int] = None, cert_hash: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], int]:
    """
    從外部 API 獲取證書詳細資料。
    
    Args:
        cert_id: 證書 ID（可選，至少需要提供 id 或 hash 其中一個）
        cert_hash: 證書 hash（可選，至少需要提供 id 或 hash 其中一個）
        
    Returns:
        Tuple[Optional[Dict], int]: (響應數據, HTTP 狀態碼)
        - 成功時返回 (response_data, status_code)
        - 錯誤時返回 (error_dict, status_code)
        
    Raises:
        不拋出異常，所有錯誤都通過返回值處理
    """
    if not cert_id and not cert_hash:
        return (
            {'error': '至少需要提供 id 或 hash 其中一個參數'},
            status.HTTP_400_BAD_REQUEST
        )
    
    # 從設置中獲取外部 API 的 base URL 和 API key
    external_api_base_url = getattr(
        settings, 
        'CERTIFICATE_API_BASE_URL', 
        'https://tc-platform-service.turingcerts.com'
    )
    
    api_key = getattr(
        settings,
        'CERTIFICATE_API_KEY',
        ''
    )
    
    if not api_key:
        logger.error("CERTIFICATE_API_KEY 未配置")
        return (
            {'error': 'API key 未配置，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # 構建外部 API URL
    external_api_url = f"{external_api_base_url}/openapi/v1/cert-record-groups/get-certificates"
    
    # 準備請求參數和標頭
    params = {}
    if cert_id:
        params['id'] = cert_id
    if cert_hash:
        params['hash'] = cert_hash
    
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
    }
    
    try:
        # 調用外部 API
        response = requests.get(
            external_api_url,
            params=params,
            headers=headers,
            timeout=30
        )
        
        # 記錄響應狀態
        logger.info(
            f"External API call to {external_api_url} returned status {response.status_code} "
            f"for cert_id={cert_id}, cert_hash={cert_hash}"
        )
        
        # 處理不同的 HTTP 狀態碼
        if response.status_code == 200:
            response_data = response.json()
            business_code = response_data.get('businessCode', 0)
            
            if business_code == 0:
                return (response_data, status.HTTP_200_OK)
            else:
                return (response_data, status.HTTP_200_OK)
        
        elif response.status_code == 400:
            try:
                response_data = response.json()
                return (response_data, status.HTTP_400_BAD_REQUEST)
            except ValueError:
                return (
                    {'error': '請求參數錯誤'},
                    status.HTTP_400_BAD_REQUEST
                )
        
        elif response.status_code == 403:
            try:
                response_data = response.json()
                return (response_data, status.HTTP_403_FORBIDDEN)
            except ValueError:
                return (
                    {'error': '沒有權限訪問此證書'},
                    status.HTTP_403_FORBIDDEN
                )
        
        elif response.status_code == 404:
            try:
                response_data = response.json()
                return (response_data, status.HTTP_404_NOT_FOUND)
            except ValueError:
                return (
                    {'error': '證書不存在'},
                    status.HTTP_404_NOT_FOUND
                )
        
        else:
            logger.error(
                f"External API returned unexpected status {response.status_code}: {response.text}"
            )
            return (
                {
                    'error': f'外部 API 返回錯誤狀態碼: {response.status_code}',
                    'details': response.text[:500]
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    except requests.exceptions.Timeout:
        logger.error(f"Timeout when calling external API for certificate id={cert_id}, hash={cert_hash}")
        return (
            {'error': '外部 API 請求超時，請稍後再試'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error when calling external API for certificate id={cert_id}, hash={cert_hash}")
        return (
            {'error': '無法連接到外部 API，請檢查網路連接'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception when calling external API: {str(e)}")
        return (
            {'error': f'外部 API 請求失敗: {str(e)}'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except ValueError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return (
            {'error': '外部 API 返回的響應格式無效'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except Exception as e:
        logger.error(f"Unexpected error when calling external API: {str(e)}", exc_info=True)
        return (
            {'error': f'獲取證書失敗: {str(e)}'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def get_pdf_url(pdf_id: str) -> Tuple[Optional[str], int]:
    """
    從外部 API 獲取證書 PDF 檔案 URL。
    
    Args:
        pdf_id: PDF 檔案 ID（從證書資料中取得）
        
    Returns:
        Tuple[Optional[str], int]: (PDF URL 或錯誤訊息, HTTP 狀態碼)
        - 成功時返回 (redirect_url, status_code) - 會重新導向到 GCS link
        - 錯誤時返回 (error_dict, status_code)
        
    Raises:
        不拋出異常，所有錯誤都通過返回值處理
    """
    if not pdf_id:
        return (
            {'error': 'pdf_id 是必填參數'},
            status.HTTP_400_BAD_REQUEST
        )
    
    # 從設置中獲取外部 API 的 base URL 和 API key
    external_api_base_url = getattr(
        settings, 
        'CERTIFICATE_API_BASE_URL', 
        'https://tc-platform-service.turingcerts.com'
    )
    
    api_key = getattr(
        settings,
        'CERTIFICATE_API_KEY',
        ''
    )
    
    if not api_key:
        logger.error("CERTIFICATE_API_KEY 未配置")
        return (
            {'error': 'API key 未配置，請聯繫管理員'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # 構建外部 API URL
    external_api_url = f"{external_api_base_url}/openapi/v1/files/get-url"
    
    # 準備請求參數和標頭
    params = {'id': pdf_id}
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
    }
    
    try:
        # 調用外部 API（不跟隨重定向，獲取重定向 URL）
        response = requests.get(
            external_api_url,
            params=params,
            headers=headers,
            timeout=30,
            allow_redirects=False  # 不自動跟隨重定向
        )
        
        # 記錄響應狀態
        logger.info(
            f"External API call to {external_api_url} returned status {response.status_code} "
            f"for pdf_id={pdf_id}"
        )
        
        # 處理重定向響應（302, 301, 307, 308）
        if response.status_code in [301, 302, 307, 308]:
            redirect_url = response.headers.get('Location')
            if redirect_url:
                return (redirect_url, status.HTTP_200_OK)
            else:
                return (
                    {'error': '外部 API 返回重定向但沒有 Location header'},
                    status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        elif response.status_code == 200:
            # 如果直接返回 200，嘗試從響應中獲取 URL
            try:
                response_data = response.json()
                # 如果響應是 JSON，可能包含 URL
                if 'url' in response_data:
                    return (response_data['url'], status.HTTP_200_OK)
                elif 'content' in response_data and 'url' in response_data['content']:
                    return (response_data['content']['url'], status.HTTP_200_OK)
                else:
                    # 如果響應是純文字 URL
                    return (response.text.strip(), status.HTTP_200_OK)
            except ValueError:
                # 如果響應不是 JSON，可能是直接的 URL
                return (response.text.strip(), status.HTTP_200_OK)
        
        elif response.status_code == 400:
            try:
                response_data = response.json()
                return (response_data, status.HTTP_400_BAD_REQUEST)
            except ValueError:
                return (
                    {'error': '請求參數錯誤'},
                    status.HTTP_400_BAD_REQUEST
                )
        
        elif response.status_code == 403:
            try:
                response_data = response.json()
                return (response_data, status.HTTP_403_FORBIDDEN)
            except ValueError:
                return (
                    {'error': '沒有權限訪問此 PDF'},
                    status.HTTP_403_FORBIDDEN
                )
        
        elif response.status_code == 404:
            try:
                response_data = response.json()
                return (response_data, status.HTTP_404_NOT_FOUND)
            except ValueError:
                return (
                    {'error': 'PDF 檔案不存在'},
                    status.HTTP_404_NOT_FOUND
                )
        
        else:
            logger.error(
                f"External API returned unexpected status {response.status_code}: {response.text}"
            )
            return (
                {
                    'error': f'外部 API 返回錯誤狀態碼: {response.status_code}',
                    'details': response.text[:500]
                },
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    except requests.exceptions.Timeout:
        logger.error(f"Timeout when calling external API for PDF id={pdf_id}")
        return (
            {'error': '外部 API 請求超時，請稍後再試'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error when calling external API for PDF id={pdf_id}")
        return (
            {'error': '無法連接到外部 API，請檢查網路連接'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception when calling external API: {str(e)}")
        return (
            {'error': f'外部 API 請求失敗: {str(e)}'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    except Exception as e:
        logger.error(f"Unexpected error when calling external API: {str(e)}", exc_info=True)
        return (
            {'error': f'獲取 PDF URL 失敗: {str(e)}'},
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )

