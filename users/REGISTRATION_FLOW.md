# 用戶註冊驗證流程說明

## 概述

用戶註冊前必須先驗證 Email 和手機號碼。驗證流程採用**順序驗證**方式：
1. **先驗證 Email**（必須）
2. **再驗證手機號碼**（必須）
3. 兩個都驗證成功後，才能進行註冊

## API 端點

### 1. 發送 OTP 驗證碼
- **端點**: `POST /auth/users/send-registration-otp/`
- **說明**: 發送 6 位數驗證碼到 Email 或手機號碼

### 2. 驗證 OTP 驗證碼
- **端點**: `POST /auth/users/verify-registration-otp/`
- **說明**: 驗證用戶輸入的 OTP 驗證碼

### 3. 註冊用戶
- **端點**: `POST /auth/users/`
- **說明**: 創建新用戶帳號（必須先完成 Email 和手機號碼驗證）

---

## 完整流程步驟

### 階段 1: Email 驗證

#### 步驟 1.1: 發送 Email OTP
**請求**:
```http
POST /auth/users/send-registration-otp/
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**成功響應** (200):
```json
{
  "message": "驗證碼已發送到您的 email",
  "expires_at": "2024-01-01T12:10:00Z",
  "method": "EMAIL"
}
```

**錯誤響應**:
- `400`: 參數錯誤或 email 已被使用
- `429`: 發送頻率過高（1 分鐘內只能發送一次）

#### 步驟 1.2: 驗證 Email OTP
**請求**:
```http
POST /auth/users/verify-registration-otp/
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "123456"
}
```

**成功響應** (200):
```json
{
  "verified": true,
  "message": "Email 驗證成功，請繼續驗證手機號碼",
  "email_verified": true,
  "phone_verified": false,
  "all_verified": false,
  "token": "臨時驗證token（可選）"
}
```

**錯誤響應**:
- `400`: 驗證碼錯誤、過期或已使用
- 驗證失敗超過 5 次需重新發送

---

### 階段 2: 手機號碼驗證

**重要**: 必須先完成 Email 驗證，才能進行手機號碼驗證。

#### 步驟 2.1: 發送手機 OTP
**請求**:
```http
POST /auth/users/send-registration-otp/
Content-Type: application/json

{
  "phone_number": "+886912345678"
}
```

**成功響應** (200):
```json
{
  "message": "驗證碼已發送到您的手機",
  "expires_at": "2024-01-01T12:10:00Z",
  "method": "SMS"
}
```

**錯誤響應**:
- `400`: 參數錯誤或手機號碼已被使用
- `429`: 發送頻率過高（1 分鐘內只能發送一次）
- `500`: 簡訊發送失敗

#### 步驟 2.2: 驗證手機 OTP
**請求**:
```http
POST /auth/users/verify-registration-otp/
Content-Type: application/json

{
  "phone_number": "+886912345678",
  "verification_email": "user@example.com",
  "code": "123456"
}
```

**重要**: 驗證手機號碼時，必須提供 `verification_email` 參數，且該 email 必須已經驗證成功。

**成功響應** (200):
```json
{
  "verified": true,
  "message": "手機號碼驗證成功，兩個驗證都已完成，可以進行註冊",
  "email_verified": true,
  "phone_verified": true,
  "all_verified": true,
  "token": "臨時驗證token（可選）"
}
```

**錯誤響應**:
- `400`:
  - 驗證碼錯誤、過期或已使用
  - Email 尚未驗證（必須先驗證 Email）
  - 未提供 `verification_email` 參數

---

### 階段 3: 註冊用戶

**重要**: 必須完成 Email 和手機號碼驗證後，才能進行註冊。

#### 步驟 3: 創建用戶帳號
**請求**:
```http
POST /auth/users/
Content-Type: application/json

{
  "email": "user@example.com",
  "phone_number": "+886912345678",
  "password": "SecurePass123!",
  "username": "newuser",
  "first_name": "名",
  "last_name": "姓",
  "occupation_category": "DOCTOR",
  "information_source": "INTERNET",
  "gender": "M",
  "birth_date": "1990-01-01",
  "residence_county": "台北市",
  "privacy_policy_accepted": true,
  // 可選：證書申請相關欄位
  "clinic_id": 1,
  "surgeon_name": "醫師姓名",
  "surgery_date": "2024-01-01",
  "consultation_clinic_id": 2,
  "consultant_name": "諮詢師姓名"
}
```

**成功響應** (201):
```json
{
  "message": "用戶創建成功",
  "data": {
    "id": 1,
    "email": "user@example.com",
    "username": "newuser"
  }
}
```

**錯誤響應**:
- `400`:
  - "請先驗證 Email 才能註冊"
  - "請先驗證手機號碼才能註冊"
  - 資料驗證失敗
  - Email 或手機號碼已被使用

---

## 前端實現建議

### 狀態管理

建議在前端維護以下狀態：

```javascript
const registrationState = {
  // Email 驗證階段
  email: '',
  emailOTPSent: false,
  emailVerified: false,
  emailOTP: '',

  // 手機驗證階段
  phoneNumber: '',
  phoneOTPSent: false,
  phoneVerified: false,
  phoneOTP: '',
  verificationEmail: '', // 用於手機驗證時提供已驗證的 email

  // 註冊階段
  canRegister: false, // emailVerified && phoneVerified
  registrationData: {},
}
```

### UI 流程建議

1. **Email 驗證頁面**
   - 輸入 Email
   - 點擊「發送驗證碼」
   - 輸入收到的 OTP
   - 點擊「驗證 Email」
   - 驗證成功後，進入手機驗證頁面

2. **手機驗證頁面**
   - 顯示已驗證的 Email（只讀）
   - 輸入手機號碼
   - 點擊「發送驗證碼」
   - 輸入收到的 OTP
   - 點擊「驗證手機號碼」
   - 驗證成功後，進入註冊表單頁面

3. **註冊表單頁面**
   - 顯示已驗證的 Email 和手機號碼（只讀）
   - 填寫其他註冊資訊
   - 提交註冊

### 錯誤處理

1. **OTP 發送頻率限制**
   - 如果收到 `429` 錯誤，顯示「請稍候再試，發送頻率過高」
   - 實現倒計時功能，防止用戶頻繁點擊

2. **OTP 驗證失敗**
   - 如果驗證碼錯誤，顯示剩餘嘗試次數
   - 如果失敗超過 5 次，提示用戶重新發送

3. **驗證狀態檢查**
   - 在註冊前，檢查 `all_verified` 是否為 `true`
   - 如果驗證狀態已過期（10 分鐘），提示用戶重新驗證

### 安全建議

1. **防止枚舉攻擊**
   - 即使 email/手機號碼不存在，API 也會返回成功
   - 前端不應該根據 API 響應判斷 email/手機號碼是否存在

2. **驗證狀態過期**
   - 驗證狀態在 cache 中保存 10 分鐘
   - 如果用戶在驗證後 10 分鐘內未完成註冊，需要重新驗證

3. **清除驗證狀態**
   - 註冊成功後，後端會自動清除驗證狀態
   - 如果用戶取消註冊，可以考慮調用清除 API（如果有的話）

---

## 注意事項

1. **驗證順序**: 必須先驗證 Email，再驗證手機號碼，順序不能顛倒

2. **驗證狀態有效期**: 驗證狀態在 cache 中保存 10 分鐘，過期後需要重新驗證

3. **OTP 有效期**: 每個 OTP 驗證碼有效期為 10 分鐘

4. **發送頻率限制**: 每個 email/手機號碼 1 分鐘內只能發送一次 OTP

5. **驗證失敗限制**: 每個 OTP 最多可以驗證失敗 5 次，超過後需重新發送

6. **手機號碼格式**: 手機號碼會自動清理格式（移除非數字字符），建議前端也進行格式驗證

7. **註冊時驗證**: 註冊時會再次檢查驗證狀態，如果驗證狀態已過期或不存在，註冊會失敗

---

## 範例代碼（JavaScript/React）

```javascript
// 發送 Email OTP
async function sendEmailOTP(email) {
  const response = await fetch('/auth/users/send-registration-otp/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  return response.json();
}

// 驗證 Email OTP
async function verifyEmailOTP(email, code) {
  const response = await fetch('/auth/users/verify-registration-otp/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code }),
  });
  return response.json();
}

// 發送手機 OTP
async function sendPhoneOTP(phoneNumber) {
  const response = await fetch('/auth/users/send-registration-otp/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone_number: phoneNumber }),
  });
  return response.json();
}

// 驗證手機 OTP
async function verifyPhoneOTP(phoneNumber, verificationEmail, code) {
  const response = await fetch('/auth/users/verify-registration-otp/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phone_number: phoneNumber,
      verification_email: verificationEmail,
      code,
    }),
  });
  return response.json();
}

// 註冊用戶
async function registerUser(userData) {
  const response = await fetch('/auth/users/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData),
  });
  return response.json();
}
```
