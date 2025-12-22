"""
證書 API 測試腳本

此腳本用於測試證書相關的 API 端點，包括：
1. 獲取模板資訊
2. 發證到新群組
3. 發證到現有群組

使用方法：
    python test_certificate_api.py

環境變量：
    - API_BASE_URL: Django API 的基礎 URL (預設: http://localhost:8000)
    - API_KEY: 外部 API 的 x-api-key (必需)
    - TEMPLATE_ID: 要使用的模板 ID
"""
import os
import sys
import json
import requests
from typing import Optional, Dict, Any
from datetime import datetime, timezone

# 配置
API_BASE_URL = os.environ.get('API_BASE_URL', 'http://localhost:8000')
API_KEY = os.environ.get('API_KEY', '42422ec94d248ec76e47e80b09780fd2b0479c14a79a6c3cebef8a7b14d8424e')
TEMPLATE_ID = int(os.environ.get('TEMPLATE_ID', '7969'))
ISSUANCE_SECRET_KEY = os.environ.get('ISSUANCE_SECRET_KEY', '1L+dRpp\{DV,')  # 發證密鑰（從模板或配置中獲取）

# 自動添加 http:// 前綴（如果缺少）
if API_BASE_URL and not API_BASE_URL.startswith(('http://', 'https://')):
    API_BASE_URL = f'http://{API_BASE_URL}'

# 顏色輸出（可選）
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'


def print_success(message: str):
    """打印成功訊息"""
    print(f"{Colors.GREEN}✓ {message}{Colors.END}")


def print_error(message: str):
    """打印錯誤訊息"""
    print(f"{Colors.RED}✗ {message}{Colors.END}")


def print_info(message: str):
    """打印資訊訊息"""
    print(f"{Colors.BLUE}ℹ {message}{Colors.END}")


def print_warning(message: str):
    """打印警告訊息"""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.END}")


def print_section(title: str):
    """打印章節標題"""
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{title}{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")


def get_template(template_id: int, api_key: str) -> Optional[Dict[str, Any]]:
    """
    獲取證書模板資訊
    
    Args:
        template_id: 模板 ID
        api_key: 外部 API 的 x-api-key
        
    Returns:
        模板資訊字典或 None（如果失敗）
    """
    print_section("步驟 1: 獲取模板資訊")
    
    url = f"{API_BASE_URL}/api/certificates/templates/get-template/"
    params = {
        'template_id': template_id,
        'api_token': api_key
    }
    headers = {}
    
    print_info(f"模板 ID: {template_id}")
    print_info(f"請求 URL: {url}")
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            business_code = data.get('businessCode', -1)
            
            if business_code == 0:
                print_success("成功獲取模板資訊！")
                template_content = data.get('content', {})
                print_info(f"模板名稱: {template_content.get('name', 'N/A')}")
                print_info(f"模板類別: {template_content.get('category', 'N/A')}")
                print_info(f"模板語言: {template_content.get('language', 'N/A')}")
                
                # 顯示 keyList（用於構建 certsData）
                key_list = template_content.get('keyList', [])
                if key_list:
                    print_info(f"模板欄位 (keyList): {len(key_list)} 個")
                    for key_item in key_list:
                        print(f"  - {key_item.get('key')} ({key_item.get('type')}): {key_item.get('description', '')}")
                
                return data
            else:
                print_error(f"獲取模板失敗: 業務代碼 {business_code}")
                print_error(f"錯誤訊息: {data.get('message', {}).get('message', 'N/A')}")
                return None
        else:
            print_error(f"獲取模板失敗: HTTP {response.status_code}")
            print_error(f"錯誤訊息: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print_error(f"獲取模板請求失敗: {str(e)}")
        return None


def build_certs_data(template_data: Dict[str, Any], certificate_application=None) -> list:
    """
    根據模板資訊構建 certsData，自動帶入會員資料、就診醫院、醫師、日期和認證序號
    
    Args:
        template_data: 模板資訊
        certificate_application: CertificateApplication 實例（可選，如果提供則自動帶入相關資料）
        
    Returns:
        certsData 列表
    """
    key_list = template_data.get('content', {}).get('keyList', [])
    
    # 構建一個示例證書資料
    cert_data = {
        'email': 'example@example.com'  # email 是必填欄位
    }
    
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
        surgeon_name = certificate_application.surgeon_name or ""
        
        # 自動帶入手術執行日期
        surgery_date = ""
        if certificate_application.surgery_date:
            surgery_date = certificate_application.surgery_date.strftime('%Y-%m-%d')
        
        # 生成或獲取認證序號
        if not certificate_application.certificate_number:
            certificate_application.certificate_number = certificate_application.generate_certificate_number()
            certificate_application.save(update_fields=['certificate_number'])
        cert_number = certificate_application.certificate_number
        
        # 設置 email
        cert_data['email'] = user.email or 'example@example.com'
    
    # 根據模板的 keyList 填入對應的資料
    for key_item in key_list:
        key = key_item.get('key')
        key_type = key_item.get('type', '')
        description = key_item.get('description', '')
        
        # 只保留 tx- 開頭的欄位
        if not key or not key.startswith('tx-'):
            continue  # 跳過非 tx- 開頭的欄位
        
        # 如果提供了 certificate_application，根據描述自動匹配欄位
        if certificate_application:
            # 根據描述判斷欄位類型並自動帶入
            if '姓名' in description or 'name' in description.lower():
                cert_data[key] = member_name
            elif '醫院' in description or 'hospital' in description.lower() or '就診' in description:
                cert_data[key] = hospital_name
            elif '醫師' in description or 'doctor' in description.lower() or '執行' in description:
                cert_data[key] = surgeon_name
            elif '日期' in description or 'date' in description.lower() or '執行日期' in description:
                cert_data[key] = surgery_date if surgery_date else "2025-12-01"
            elif '序號' in description or 'number' in description.lower() or 'certificate no' in description.lower() or '認證' in description:
                cert_data[key] = cert_number
            elif '獎狀' in description or 'certificate' in description.lower():
                cert_data[key] = "示例獎狀"
            else:
                # 如果用戶在 certificate_data 中提供了該欄位的值，使用用戶的值
                if certificate_application.certificate_data and key in certificate_application.certificate_data:
                    cert_data[key] = certificate_application.certificate_data[key]
                else:
                    cert_data[key] = f"示例{key}"
        else:
            # 沒有提供 certificate_application，使用示例值
            if 'string' in key_type or 'text' in key_type:
                # 根據描述判斷欄位類型
                if '姓名' in description or 'name' in description.lower():
                    cert_data[key] = "張三"
                elif '日期' in description or 'date' in description.lower():
                    cert_data[key] = "2025-12-01"
                elif '獎狀' in description or 'certificate' in description.lower():
                    cert_data[key] = "示例獎狀"
                else:
                    cert_data[key] = f"示例{key}"
            elif 'number' in key_type or 'integer' in key_type:
                cert_data[key] = 123
            elif 'date' in key_type:
                cert_data[key] = "2025-12-01"
            elif 'email' in key_type:
                cert_data[key] = "example@example.com"
            else:
                cert_data[key] = f"示例值_{key}"
    
    return [cert_data]


def issue_certificates_to_new_group(
    template_id: int,
    api_key: str,
    template_data: Optional[Dict[str, Any]] = None
) -> Optional[int]:
    """
    發證到新的證書群組
    
    Args:
        template_id: 模板 ID
        api_key: 外部 API 的 x-api-key
        template_data: 模板資訊（用於構建 certsData）
        
    Returns:
        證書群組 ID 或 None（如果失敗）
    """
    print_section("步驟 2: 發證到新群組")
    
    url = f"{API_BASE_URL}/api/certificates/issue-to-new-group/"
    params = {
        'api_token': api_key
    }
    headers = {
        'Content-Type': 'application/json'
    }
    
    # 構建請求體
    if template_data:
        certs_data = build_certs_data(template_data)
    else:
        # 如果沒有模板資料，使用空的 certsData
        certs_data = [{}]
        print_warning("沒有模板資料，使用空的 certsData")

    print(certs_data)
    print(ISSUANCE_SECRET_KEY)
    
    payload = {
        'templateId': template_id,
        'name': f'測試證書群組_{template_id}',
        'certsData': certs_data,
        'isDownloadButtonEnabled': True,
        'skipSendingNotification': True,
        'setVisibilityPublic': True,
        'certPassword': ISSUANCE_SECRET_KEY if ISSUANCE_SECRET_KEY else '',  # 發證密鑰
        'certRecordRemark': '測試發證',
        'pdfProtectionPassword': '',
        'autoNotificationTime': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),  # 當前時間 ISO 8601 格式
        'customEmail': {
            'subject': '證書發放通知',
            'description': '您的證書已準備就緒',
            'contactEmail': 'contact@example.com'
        }
    }
    
    print_info(f"模板 ID: {template_id}")
    print_info(f"證書數量: {len(certs_data)}")
    print_info(f"請求 URL: {url}")
    
    try:
        response = requests.post(url, params=params, headers=headers, json=payload, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            business_code = data.get('businessCode', -1)
            
            if business_code == 0:
                certificate_group_id = data.get('content', {}).get('id')
                print_success("成功發證到新群組！")
                print_info(f"證書群組 ID: {certificate_group_id}")
                return certificate_group_id
            else:
                print_error(f"發證失敗: 業務代碼 {business_code}")
                print_error(f"錯誤訊息: {data.get('message', {}).get('message', 'N/A')}")
                print_error(f"完整響應: {json.dumps(data, indent=2, ensure_ascii=False)}")
                return None
        else:
            print_error(f"發證失敗: HTTP {response.status_code}")
            try:
                error_data = response.json()
                print_error(f"錯誤訊息: {json.dumps(error_data, indent=2, ensure_ascii=False)}")
            except:
                print_error(f"錯誤訊息: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print_error(f"發證請求失敗: {str(e)}")
        return None


def issue_certificates_to_existing_group(
    certificate_group_id: int,
    api_key: str,
    template_data: Optional[Dict[str, Any]] = None
) -> bool:
    """
    發證到現有的證書群組
    
    Args:
        certificate_group_id: 證書群組 ID
        api_key: 外部 API 的 x-api-key
        template_data: 模板資訊（用於構建 certsData）
        
    Returns:
        True 如果成功，False 如果失敗
    """
    print_section("步驟 3: 發證到現有群組（可選）")
    
    url = f"{API_BASE_URL}/api/certificates/issue-to-existing-group/"
    params = {
        'api_token': api_key
    }
    headers = {
        'Content-Type': 'application/json'
    }
    
    # 構建請求體
    if template_data:
        certs_data = build_certs_data(template_data)
    else:
        certs_data = [{}]
        print_warning("沒有模板資料，使用空的 certsData")
    
    payload = {
        'certRecordGroupId': certificate_group_id,
        'certsData': certs_data,
        'isDownloadButtonEnabled': True,
        'skipSendingNotification': True,
        'setVisibilityPublic': True,
        'certPassword': ISSUANCE_SECRET_KEY if ISSUANCE_SECRET_KEY else '',  # 發證密鑰
        'certRecordRemark': '測試發證到現有群組',
        'pdfProtectionPassword': '',
        'autoNotificationTime': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),  # 當前時間 ISO 8601 格式
        'customEmail': {
            'subject': '證書發放通知',
            'description': '您的證書已準備就緒',
            'contactEmail': 'contact@example.com'
        }
    }
    
    print_info(f"證書群組 ID: {certificate_group_id}")
    print_info(f"證書數量: {len(certs_data)}")
    
    try:
        response = requests.post(url, params=params, headers=headers, json=payload, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            business_code = data.get('businessCode', -1)
            
            if business_code == 0:
                print_success("成功發證到現有群組！")
                return True
            else:
                print_error(f"發證失敗: 業務代碼 {business_code}")
                print_error(f"錯誤訊息: {data.get('message', {}).get('message', 'N/A')}")
                return False
        else:
            print_error(f"發證失敗: HTTP {response.status_code}")
            try:
                error_data = response.json()
                print_error(f"錯誤訊息: {json.dumps(error_data, indent=2, ensure_ascii=False)}")
            except:
                print_error(f"錯誤訊息: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_error(f"發證請求失敗: {str(e)}")
        return False


def main():
    """主函數"""
    print_section("證書 API 測試腳本")
    print_info(f"API 基礎 URL: {API_BASE_URL}")
    print_info(f"模板 ID: {TEMPLATE_ID}")
    if ISSUANCE_SECRET_KEY:
        masked_key = '*' * (len(ISSUANCE_SECRET_KEY) - 4) + ISSUANCE_SECRET_KEY[-4:] if len(ISSUANCE_SECRET_KEY) > 4 else '****'
        print_info(f"發證密鑰: {masked_key}")
    else:
        print_warning("未設置發證密鑰 (ISSUANCE_SECRET_KEY)，將使用空字串")
    print()
    
    # 檢查必要的環境變量
    if API_KEY == 'your_api_key_here':
        print_warning("請設置 API_KEY 環境變量")
        print_warning("或在腳本中修改 API_KEY 變量")
        response = input("是否繼續測試？(y/n): ")
        if response.lower() != 'y':
            print_info("測試已取消")
            return
    
    # 提示發證密鑰
    if not ISSUANCE_SECRET_KEY:
        print_warning("注意：未設置發證密鑰，可能會導致業務代碼 9695 錯誤")
        print_warning("請設置 ISSUANCE_SECRET_KEY 環境變量或修改腳本中的變量")
        response = input("是否繼續測試？(y/n): ")
        if response.lower() != 'y':
            print_info("測試已取消")
            return
    
    # 步驟 1: 獲取模板資訊
    template_data = get_template(TEMPLATE_ID, API_KEY)
    if not template_data:
        print_warning("無法獲取模板資訊，將使用空的 certsData")
    
    # 步驟 2: 發證到新群組
    certificate_group_id = issue_certificates_to_new_group(
        TEMPLATE_ID,
        API_KEY,
        template_data
    )
    
    if certificate_group_id:
        print_success(f"測試完成！證書群組 ID: {certificate_group_id}")
        
        # 可選：發證到現有群組
        response = input("\n是否要測試發證到現有群組？(y/n): ")
        if response.lower() == 'y':
            issue_certificates_to_existing_group(
                certificate_group_id,
                API_KEY,
                template_data
            )
    else:
        print_error("發證失敗，測試終止")
        sys.exit(1)
    
    print_section("測試完成")


if __name__ == '__main__':
    main()

