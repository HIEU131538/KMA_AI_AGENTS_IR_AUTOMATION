# API CONTRACT — KMA HR Management Security Lab

## 1. Mục đích tài liệu

Tài liệu này mô tả API contract giữa ba nhóm thành phần trong hệ thống:

* Backend/Frontend HR Management System
* Red Team / Attack Scenario Builder
* SIEM / Autonomous AI Agent

Mục tiêu của tài liệu là giúp Red Team biết endpoint nào dùng để xây dựng attack chain, đồng thời giúp AI Agent biết log nào cần đọc, trường nào cần phân tích, label nào biểu thị hành vi tấn công và MITRE ATT&CK mapping dự kiến.

Toàn bộ request từ frontend, Red Team script hoặc tester phải đi qua WAF:

```text
http://localhost:8080
```

Không gọi trực tiếp backend nội bộ:

```text
http://kma-app:8000
```

Luồng chuẩn:

```text
Client / Attacker / Frontend
    ↓
localhost:8080
    ↓
kma-waf / Nginx + ModSecurity
    ↓
kma-app / FastAPI
    ↓
kma-db / PostgreSQL
    ↓
logs/app, logs/nginx, logs/waf
    ↓
kma-siem / AI Agent
```

---

## 2. Base URL

```text
Base URL: http://localhost:8080
```

---

## 3. Authentication

Hệ thống sử dụng JWT Bearer Token.

Header chuẩn:

```http
Authorization: Bearer <JWT_TOKEN>
```

JWT payload thống nhất:

```json
{
  "sub": "employee01",
  "role": "employee",
  "user_id": 2,
  "jti": "token-id-unique",
  "exp": 1779612376
}
```

Các role chính:

```text
admin
manager
employee
```

---

## 4. Logging Schema

Backend ghi log JSON tại:

```text
logs/app/app.log
```

Mỗi request sinh một dòng JSON theo schema:

```json
{
  "timestamp": "2026-05-08T21:00:00Z",
  "event_id": "uuid",
  "service": "kma-backend",
  "client_ip": "172.20.0.100",
  "request": {
    "method": "GET",
    "url": "/api/v1/employees/1",
    "query_params": {},
    "headers": {
      "host": "localhost:8080",
      "user-agent": "curl/8.0",
      "x-forwarded-for": "1.2.3.4",
      "x-real-ip": "1.2.3.4",
      "content-type": "application/json"
    },
    "body": null
  },
  "response": {
    "status_code": 200,
    "latency_ms": 45
  },
  "auth_context": {
    "user_id": 2,
    "username": "employee01",
    "role": "employee",
    "jti": "token-id-unique"
  },
  "security_metadata": {
    "waf_decision": "allowed",
    "detected_attack": "bola_attempt",
    "mitre_technique": "T1190",
    "message": "Authenticated user accessed another employee profile"
  }
}
```

Các log khác:

```text
logs/nginx/access.log    → request đi qua WAF/Nginx
logs/nginx/error.log     → lỗi WAF/Nginx
logs/waf/audit.log       → ModSecurity audit log
logs/app/app.log         → backend JSON log
```

---

## 5. Danh sách detected_attack label

| Label                                        | Ý nghĩa                                              | Nguồn log chính |
| -------------------------------------------- | ---------------------------------------------------- | --------------- |
| `none`                                       | Request bình thường                                  | app.log         |
| `failed_login`                               | Đăng nhập sai username/password                      | app.log         |
| `disabled_user_login`                        | User bị disable cố đăng nhập                         | app.log         |
| `jwt_unverified_validation`                  | Endpoint lab đọc JWT không verify chữ ký             | app.log         |
| `bola_attempt`                               | User đã xác thực truy cập hồ sơ người khác           | app.log         |
| `mass_assignment_role_escalation`            | User thường gửi `role=admin` để leo thang quyền      | app.log         |
| `mass_assignment_role_update`                | Backend chấp nhận field role từ client               | app.log         |
| `ssrf_internal_request`                      | `source_url` trỏ vào service nội bộ Docker lab       | app.log         |
| `external_url_blocked_by_lab_scope`          | URL ngoài phạm vi lab bị backend chặn                | app.log         |
| `ssrf_metadata_request_blocked_by_lab_scope` | Metadata URL bị backend chặn theo policy lab         | app.log         |
| `rag_poisoning_surface_access`               | Upload CV, bề mặt cho RAG poisoning                  | app.log         |
| `admin_log_access`                           | Admin gọi API đọc security log                       | app.log         |
| `ai_assisted_rce_attempt`                    | Endpoint reboot-service nhận field command nguy hiểm | app.log         |
| `external_fetch_requested`                   | Endpoint fetch-external được gọi                     | app.log         |
| `backend_exception`                          | Backend phát sinh exception chưa xử lý               | app.log         |

---

# 6. Endpoint Contract

---

## 6.1. System / Health

### Endpoint

```http
GET /health
```

### Mục tiêu

Kiểm tra backend có chạy sau WAF không.

### Auth

Không yêu cầu JWT.

### Response mẫu

```json
{
  "status": "ok",
  "service": "kma-app",
  "ip": "172.20.0.3"
}
```

### Log

```json
{
  "detected_attack": "none",
  "message": null
}
```

### Ghi chú

Dùng để kiểm tra luồng:

```text
localhost:8080 → kma-waf → kma-app
```

---

# 7. Auth APIs

---

## 7.1. Password Login

### Endpoint

```http
POST /auth/login
```

### Mục tiêu

Đăng nhập bằng username/password và nhận JWT.

### Auth

Không yêu cầu JWT.

### Input JSON

```json
{
  "username": "admin",
  "password": "admin123"
}
```

hoặc:

```json
{
  "username": "employee01",
  "password": "employee123"
}
```

### Output JSON thành công

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

### Output JSON thất bại

```json
{
  "detail": "Invalid username or password"
}
```

### Log label

| Tình huống    | detected_attack       | MITRE  |
| ------------- | --------------------- | ------ |
| Login đúng    | `none`                | `null` |
| Login sai     | `failed_login`        | `null` |
| User disabled | `disabled_user_login` | `null` |

### Log message mẫu

```text
User logged in successfully
```

hoặc:

```text
Login failed: wrong password for admin
```

---

## 7.2. Validate JWT

### Endpoint

```http
GET /auth/session/validate
```

### Mục tiêu

Kiểm tra JWT đúng chuẩn: chữ ký, hạn token, user, trạng thái revoke.

### Auth

Yêu cầu JWT.

### Header

```http
Authorization: Bearer <JWT_TOKEN>
```

### Output JSON thành công

```json
{
  "valid": true,
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  },
  "jti": "uuid"
}
```

### Output lỗi

```json
{
  "detail": "Missing bearer token"
}
```

hoặc:

```json
{
  "detail": "Token has been revoked"
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "JWT session validated successfully"
}
```

---

## 7.3. Validate JWT Lab — JWT Forgery Surface

### Endpoint

```http
GET /auth/session/validate-lab
```

### Mục tiêu

Endpoint cố tình yếu để mô phỏng JWT Forgery. Endpoint này đọc JWT payload mà không verify chữ ký.

### Auth

Có thể gửi JWT, nhưng endpoint cố tình không verify an toàn.

### Header

```http
Authorization: Bearer <JWT_TOKEN>
```

### Output JSON

```json
{
  "valid": true,
  "claims": {
    "sub": "admin",
    "role": "admin",
    "user_id": 1,
    "jti": "uuid",
    "exp": 1779612376
  },
  "warning": "Lab mode: JWT signature is NOT verified here. This endpoint is intentionally vulnerable."
}
```

### Log label

```json
{
  "detected_attack": "jwt_unverified_validation",
  "mitre_technique": "T1550.004",
  "message": "JWT payload parsed without signature verification"
}
```

### MITRE mapping

```text
T1550.004 — Use Alternate Authentication Material: Web Session Cookie
```

Mapping này là mapping dự kiến, cần rà soát lại khi viết báo cáo cuối.

---

## 7.4. Logout

### Endpoint

```http
POST /auth/logout
```

### Mục tiêu

Revoke JWT thông qua `jti`.

### Auth

Yêu cầu JWT.

### Output JSON

```json
{
  "message": "Logout successful",
  "revoked_jti": "uuid"
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "User logged out and token revoked"
}
```

---

# 8. FIDO2 / WebAuthn APIs

---

## 8.1. Register Passkey Start

### Endpoint

```http
POST /auth/fido2/register/start
```

### Mục tiêu

Backend tạo challenge đăng ký FIDO2/WebAuthn.

### Auth

Yêu cầu JWT. User cần login password trước để bind passkey vào tài khoản.

### Input

Không cần body.

### Output JSON rút gọn

```json
{
  "rp": {
    "name": "KMA HR Management",
    "id": "localhost"
  },
  "user": {
    "id": "...",
    "name": "employee01",
    "displayName": "employee01"
  },
  "challenge": "...",
  "pubKeyCredParams": []
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "FIDO2 registration challenge generated"
}
```

---

## 8.2. Register Passkey Finish

### Endpoint

```http
POST /auth/fido2/register/finish
```

### Mục tiêu

Backend verify credential do browser/Windows Hello tạo ra và lưu public key vào PostgreSQL.

### Auth

Yêu cầu JWT.

### Input JSON

```json
{
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {
      "attestationObject": "...",
      "clientDataJSON": "..."
    },
    "type": "public-key"
  }
}
```

### Output JSON

```json
{
  "verified": true,
  "message": "FIDO2 credential registered successfully",
  "credential": {
    "id": 1,
    "credential_id": "...",
    "sign_count": 0
  }
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "FIDO2 credential registered successfully"
}
```

### Ghi chú

Server không lưu vân tay, Face ID hoặc private key. Server chỉ lưu:

```text
credential_id
public_key
sign_count
```

---

## 8.3. Login Passkey Start

### Endpoint

```http
POST /auth/fido2/login/start
```

### Mục tiêu

Backend tạo authentication challenge cho user đã đăng ký passkey.

### Auth

Không yêu cầu JWT.

### Input JSON

```json
{
  "username": "employee01"
}
```

### Output JSON rút gọn

```json
{
  "challenge": "...",
  "rpId": "localhost",
  "allowCredentials": []
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "FIDO2 authentication challenge generated"
}
```

---

## 8.4. Login Passkey Finish

### Endpoint

```http
POST /auth/fido2/login/finish
```

### Mục tiêu

Backend verify chữ ký WebAuthn bằng public key đã lưu, sau đó cấp JWT.

### Auth

Không yêu cầu JWT.

### Input JSON

```json
{
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {
      "authenticatorData": "...",
      "clientDataJSON": "...",
      "signature": "...",
      "userHandle": "..."
    },
    "type": "public-key"
  }
}
```

### Output JSON

```json
{
  "verified": true,
  "message": "FIDO2 login successful",
  "access_token": "<jwt>",
  "token_type": "bearer",
  "user": {
    "id": 2,
    "username": "employee01",
    "role": "employee"
  }
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "FIDO2 login verified and JWT issued"
}
```

---

# 9. Employee / HR APIs

---

## 9.1. List Employees

### Endpoint

```http
GET /api/v1/employees
```

### Mục tiêu

Admin/manager xem danh sách nhân sự.

### Auth

Yêu cầu JWT.

### Role

```text
admin
manager
```

### Output JSON

```json
{
  "count": 3,
  "employees": [
    {
      "id": 1,
      "user_id": 1,
      "full_name": "Duong Ngoc Hieu",
      "department": "Board",
      "position": "Director",
      "salary": 50000000,
      "phone": "0900000001",
      "email": "admin@kma.local"
    }
  ]
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "Employee list requested from PostgreSQL"
}
```

### Ghi chú Red Team

Sau Mass Assignment thành công, `employee01` có thể lên `admin` và gọi endpoint này.

---

## 9.2. Get My Profile

### Endpoint

```http
GET /api/v1/employees/me
```

### Mục tiêu

User xem hồ sơ của chính mình.

### Auth

Yêu cầu JWT.

### Output JSON

```json
{
  "id": 2,
  "user_id": 2,
  "full_name": "Nguyen Quang Dat",
  "department": "Human Resources",
  "position": "HR Officer",
  "salary": 20000000,
  "phone": "0999999999",
  "email": "employee01@kma.local"
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "Current employee profile requested"
}
```

---

## 9.3. Get Employee Detail — BOLA Surface

### Endpoint

```http
GET /api/v1/employees/{employee_id}
```

### Mục tiêu

Endpoint cài lỗi BOLA có chủ đích.

### Auth

Yêu cầu JWT.

### Input path

```text
employee_id: integer
```

Ví dụ:

```http
GET /api/v1/employees/1
```

### Cách đúng đáng lẽ phải là

```text
Admin/manager được xem tất cả.
Employee chỉ được xem hồ sơ của chính mình.
```

### Cách cố tình sai trong lab

```text
Chỉ cần có JWT hợp lệ là xem được bất kỳ employee_id nào.
```

### Kịch bản Red Team

```text
employee01 login
↓
GET /api/v1/employees/me
↓
thấy hồ sơ của mình là employee_id=2
↓
GET /api/v1/employees/1
↓
vẫn đọc được hồ sơ admin/director
```

### Output JSON khi BOLA thành công

```json
{
  "id": 1,
  "user_id": 1,
  "full_name": "Duong Ngoc Hieu",
  "department": "Board",
  "position": "Director",
  "salary": 50000000,
  "phone": "0900000001",
  "email": "admin@kma.local"
}
```

### Log label

```json
{
  "detected_attack": "bola_attempt",
  "mitre_technique": "T1190",
  "message": "Authenticated user accessed another employee profile. username=employee01, user_id=2, requested_employee_id=1, target_owner_user_id=1"
}
```

### MITRE mapping dự kiến

```text
T1190 — Exploit Public-Facing Application
```

Cần rà soát lại mapping trong báo cáo cuối vì BOLA là lỗi logic/API Authorization, không phải lúc nào cũng map trực tiếp vào một technique duy nhất.

---

## 9.4. Create Employee

### Endpoint

```http
POST /api/v1/employees
```

### Mục tiêu

Admin tạo hồ sơ nhân sự mới.

### Auth

Yêu cầu JWT.

### Role

```text
admin
```

### Input JSON

```json
{
  "user_id": 4,
  "full_name": "New Employee",
  "department": "Finance",
  "position": "Accountant",
  "salary": 18000000,
  "phone": "0900000004",
  "email": "new.employee@kma.local"
}
```

### Output JSON

```json
{
  "message": "Employee created successfully",
  "employee": {
    "id": 4,
    "user_id": 4,
    "full_name": "New Employee",
    "department": "Finance"
  }
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "Employee created: employee_id=4"
}
```

---

## 9.5. Update Employee

### Endpoint

```http
PATCH /api/v1/employees/{employee_id}
```

### Mục tiêu

Admin cập nhật hồ sơ nhân sự.

### Auth

Yêu cầu JWT.

### Role

```text
admin
```

### Input JSON

```json
{
  "position": "Senior Accountant",
  "salary": 22000000
}
```

### Output JSON

```json
{
  "message": "Employee updated successfully",
  "employee": {
    "id": 4,
    "position": "Senior Accountant",
    "salary": 22000000
  }
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "Employee updated: employee_id=4"
}
```

---

## 9.6. Delete Employee

### Endpoint

```http
DELETE /api/v1/employees/{employee_id}
```

### Mục tiêu

Admin xóa hồ sơ nhân sự.

### Auth

Yêu cầu JWT.

### Role

```text
admin
```

### Output JSON

```json
{
  "message": "Employee deleted successfully",
  "employee_id": 4
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "Employee deleted: employee_id=4"
}
```

---

## 9.7. Update Profile — Mass Assignment Surface

### Endpoint

```http
PATCH /api/v1/employees/profile
```

### Mục tiêu

Endpoint cài lỗi Mass Assignment có chủ đích.

### Auth

Yêu cầu JWT.

### Cách đúng đáng lẽ phải là

User chỉ được sửa:

```text
full_name
phone
email
```

### Cách cố tình sai trong lab

Backend chấp nhận thêm field nhạy cảm:

```json
{
  "role": "admin"
}
```

### Input JSON

```json
{
  "full_name": "Nguyen Quang Dat",
  "phone": "0999999999",
  "email": "employee01@kma.local",
  "role": "admin"
}
```

### Output JSON

```json
{
  "message": "Profile updated",
  "profile": {
    "employee_id": 2,
    "user_id": 2,
    "username": "employee01",
    "full_name": "Nguyen Quang Dat",
    "phone": "0999999999",
    "email": "employee01@kma.local",
    "role": "admin"
  },
  "lab_note": "This endpoint intentionally accepts role field for Mass Assignment demonstration."
}
```

### Log label

```json
{
  "detected_attack": "mass_assignment_role_escalation",
  "mitre_technique": "T1078",
  "message": "Mass Assignment attempt: user=employee01 changed role from employee to admin"
}
```

### MITRE mapping dự kiến

```text
T1078 — Valid Accounts
```

### Kịch bản Red Team

```text
employee01 login
↓
PATCH /api/v1/employees/profile
↓
body chứa role=admin
↓
database cập nhật employee01 thành admin
↓
employee01 gọi được endpoint quyền cao
```

---

## 9.8. List Departments

### Endpoint

```http
GET /api/v1/departments
```

### Mục tiêu

Trả danh sách phòng ban mẫu.

### Auth

Không bắt buộc hoặc tùy cấu hình backend hiện tại.

### Output JSON

```json
{
  "departments": [
    {
      "id": 1,
      "name": "Board"
    },
    {
      "id": 2,
      "name": "Human Resources"
    }
  ]
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "Departments listed"
}
```

---

# 10. Tools / Vulnerability Gateway APIs

---

## 10.1. Export PDF — Controlled SSRF Surface

### Endpoint

```http
POST /api/v1/tools/export-pdf
```

### Mục tiêu

Mô phỏng chức năng export PDF bằng cách backend nhận `source_url`, fetch nội dung URL và giả lập tạo PDF.

### Auth

Yêu cầu JWT.

### Input JSON

```json
{
  "source_url": "http://kma-app:8000/health"
}
```

### Lỗi chủ đích

Endpoint mô phỏng SSRF có kiểm soát:

```text
Backend nhận URL từ user.
Backend fetch target nội bộ trong Docker lab.
Không whitelist domain theo chuẩn production.
Ghi log khi URL trỏ tới service nội bộ.
```

### Output JSON blind mode

```json
{
  "message": "PDF export simulated",
  "source_url": "http://kma-app:8000/health",
  "analysis": {
    "source_url": "http://kma-app:8000/health",
    "scheme": "http",
    "hostname": "kma-app",
    "resolved_ips": [
      "172.20.0.3"
    ],
    "allowed_ips": [
      "172.20.0.3"
    ],
    "is_allowed_internal_lab_target": true,
    "is_metadata_target": false
  },
  "fetch_executed": true,
  "fetch_result": {
    "status_code": 200,
    "content_type": "application/json",
    "content_length": null,
    "final_url": "http://kma-app:8000/health",
    "preview": null
  },
  "mode": "blind",
  "lab_note": "Controlled SSRF lab endpoint. In blind mode, response body is not returned."
}
```

### Log label

```json
{
  "detected_attack": "ssrf_internal_request",
  "mitre_technique": "T1190",
  "message": "source_url points to internal/private Docker lab address. hostname=kma-app, resolved_ips=['172.20.0.3'], allowed_ips=['172.20.0.3']"
}
```

### MITRE mapping dự kiến

```text
T1190 — Exploit Public-Facing Application
```

### Payload metadata

```json
{
  "source_url": "http://169.254.169.254/latest/meta-data/"
}
```

Nếu WAF bật blocking mode, request có thể bị chặn với:

```text
403 Forbidden
nginx
```

Log chính khi đó nằm ở:

```text
logs/nginx/access.log
logs/waf/audit.log
```

Nếu request lọt tới backend, backend không fetch thật metadata service mà trả:

```json
{
  "message": "PDF export rejected by controlled SSRF lab policy",
  "fetch_executed": false,
  "reason": "metadata service target is not fetched in this controlled lab"
}
```

Log label:

```json
{
  "detected_attack": "ssrf_metadata_request_blocked_by_lab_scope",
  "mitre_technique": "T1190"
}
```

---

## 10.2. Upload CV

### Endpoint

```http
POST /api/v1/tools/upload-cv
```

### Mục tiêu

Upload CV ứng viên. Dùng làm bề mặt cho kịch bản RAG poisoning hoặc xử lý file độc hại trong phase nâng cao.

### Auth

Yêu cầu JWT.

### Input

```http
multipart/form-data
file=<cv_file>
```

### Output JSON

```json
{
  "message": "CV uploaded",
  "filename": "sample_cv.txt",
  "content_type": "text/plain"
}
```

### Log label

```json
{
  "detected_attack": "rag_poisoning_surface_access",
  "mitre_technique": "T1562",
  "message": "CV uploaded: sample_cv.txt"
}
```

### MITRE mapping dự kiến

```text
T1562 — Impair Defenses
```

Mapping này là mapping tạm để phục vụ lab/AI Agent, cần rà soát thêm khi viết báo cáo.

---

## 10.3. Fetch External

### Endpoint

```http
GET /api/v1/tools/fetch-external?url=<url>
```

### Mục tiêu

Endpoint mô phỏng việc lấy dữ liệu từ bên thứ ba. Hiện tại không bật fetch thật tự do.

### Auth

Yêu cầu JWT.

### Output JSON

```json
{
  "message": "External fetch request received",
  "url": "https://example.com",
  "mode": "simulated",
  "note": "Real outbound fetch is not enabled in this controlled lab."
}
```

### Log label

```json
{
  "detected_attack": "external_fetch_requested",
  "mitre_technique": "T1048",
  "message": "External fetch requested: https://example.com"
}
```

---

# 11. Admin / SOC APIs

---

## 11.1. Admin Status

### Endpoint

```http
GET /api/v1/admin/status
```

### Mục tiêu

Trả trạng thái cơ bản của backend, DB, WAF, SIEM.

### Auth

Yêu cầu JWT.

### Role

```text
admin
manager
```

### Output JSON

```json
{
  "status": "healthy",
  "service": "kma-backend",
  "db": "connected",
  "waf": "behind-kma-waf",
  "siem": "log-volume-enabled"
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "Admin status endpoint requested"
}
```

---

## 11.2. Admin System Status

### Endpoint

```http
GET /api/v1/admin/system-status
```

### Mục tiêu

Trả trạng thái chi tiết hơn cho admin/SOC.

### Auth

Yêu cầu JWT.

### Role

```text
admin
manager
```

### Output JSON mẫu

```json
{
  "status": "healthy",
  "service": "kma-backend",
  "container_ip": "172.20.0.3",
  "database": "kma-db:5432",
  "waf": "kma-waf:172.20.0.2",
  "siem": "kma-siem:172.20.0.4",
  "ai_agent": "kma-ai-agent:172.20.0.5",
  "cpu_load_avg": [0.1, 0.2, 0.3],
  "log_path": "/var/log/kma-app/app.log"
}
```

### Log label

```json
{
  "detected_attack": "none",
  "message": "System status requested by admin/SOC"
}
```

---

## 11.3. Security Logs

### Endpoint

```http
GET /api/v1/admin/security-logs?limit=20
```

### Mục tiêu

Endpoint cho admin đọc log bảo mật trực tiếp từ backend.

### Auth

Yêu cầu JWT.

### Role

```text
admin
```

### Output JSON

```json
{
  "message": "Security logs fetched",
  "count": 20,
  "logs": []
}
```

### Log label

```json
{
  "detected_attack": "admin_log_access",
  "mitre_technique": "T1059",
  "message": "Security logs requested through admin API"
}
```

---

## 11.4. Reboot Service — AI-assisted RCE Surface

### Endpoint

```http
POST /api/v1/admin/reboot-service
```

### Mục tiêu

Endpoint mô phỏng hành động quản trị service. Nếu AI Agent bị prompt injection/RAG poisoning và gọi endpoint này với field `command`, có thể mô phỏng AI-assisted RCE.

### Auth

Yêu cầu JWT.

### Role

```text
admin
```

### Input JSON bình thường

```json
{
  "service_name": "kma-app",
  "reason": "maintenance"
}
```

### Input JSON nguy hiểm

```json
{
  "service_name": "kma-app",
  "reason": "incident response",
  "command": "whoami"
}
```

### Output JSON

```json
{
  "message": "Service reboot simulated",
  "service_name": "kma-app",
  "reason": "incident response",
  "command_received": true,
  "status": "simulated_only"
}
```

### Log label

Nếu có field `command`:

```json
{
  "detected_attack": "ai_assisted_rce_attempt",
  "mitre_technique": "LLM02",
  "message": "Dangerous command field received in reboot-service request"
}
```

Nếu không có field `command`:

```json
{
  "detected_attack": "admin_service_reboot_requested",
  "message": "Service reboot requested"
}
```

---

# 12. Red Team Attack Chain mẫu

## Chain 1 — BOLA

```text
1. Login employee01
2. GET /api/v1/employees/me
3. GET /api/v1/employees/1
4. Quan sát dữ liệu admin bị lộ
5. Kiểm tra logs/app/app.log
```

Expected log:

```json
{
  "detected_attack": "bola_attempt",
  "mitre_technique": "T1190"
}
```

---

## Chain 2 — Mass Assignment Privilege Escalation

```text
1. Login employee01
2. PATCH /api/v1/employees/profile
3. Body chứa "role": "admin"
4. Login lại hoặc validate token
5. GET /api/v1/employees
```

Expected log:

```json
{
  "detected_attack": "mass_assignment_role_escalation",
  "mitre_technique": "T1078"
}
```

---

## Chain 3 — SSRF Internal Request

```text
1. Login admin hoặc user đã leo quyền
2. POST /api/v1/tools/export-pdf
3. source_url = http://kma-app:8000/health
4. Backend fetch service nội bộ Docker lab
5. Kiểm tra app log
```

Expected log:

```json
{
  "detected_attack": "ssrf_internal_request",
  "mitre_technique": "T1190"
}
```

---

## Chain 4 — WAF Blocks Metadata SSRF

```text
1. Login admin
2. POST /api/v1/tools/export-pdf
3. source_url = http://169.254.169.254/latest/meta-data/
4. WAF có thể trả 403 Forbidden
5. Kiểm tra logs/nginx/access.log và logs/waf/audit.log
```

Expected WAF behavior:

```text
403 Forbidden
```

Expected log source:

```text
logs/nginx/access.log
logs/waf/audit.log
```

---

## Chain 5 — Upload CV / RAG Poisoning Surface

```text
1. Login user hợp lệ
2. POST /api/v1/tools/upload-cv
3. Upload file CV
4. Kiểm tra app log
```

Expected log:

```json
{
  "detected_attack": "rag_poisoning_surface_access",
  "mitre_technique": "T1562"
}
```

---

# 13. AI Agent Integration Notes

AI Agent nên đọc tối thiểu các log sau:

```text
/logs/app/app.log
/logs/nginx/access.log
/logs/waf/audit.log
```

AI Agent nên ưu tiên các trường:

```text
timestamp
event_id
client_ip
request.method
request.url
request.headers.user-agent
response.status_code
auth_context.user_id
auth_context.username
auth_context.role
security_metadata.detected_attack
security_metadata.mitre_technique
security_metadata.message
```

Logic phân tích gợi ý:

```text
Nếu detected_attack != none:
    tạo alert

Nếu detected_attack = bola_attempt:
    severity = medium/high
    action = watch user, correlate employee_id access

Nếu detected_attack = mass_assignment_role_escalation:
    severity = high/critical
    action = recommend revoke token, downgrade role, alert SOC

Nếu detected_attack = ssrf_internal_request:
    severity = high
    action = inspect target host, correlate WAF log

Nếu WAF trả 403 với metadata payload:
    severity = high
    action = mark blocked SSRF attempt

Nếu failed_login lặp lại nhiều lần theo client_ip:
    severity = medium/high
    action = brute-force suspicion
```

---

# 14. Quick Test Commands

## Login admin

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

## Login employee01

```bash
EMP_TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"employee01","password":"employee123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

## BOLA test

```bash
curl http://localhost:8080/api/v1/employees/1 \
  -H "Authorization: Bearer $EMP_TOKEN"
```

## Mass Assignment test

```bash
curl -X PATCH http://localhost:8080/api/v1/employees/profile \
  -H "Authorization: Bearer $EMP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "Nguyen Quang Dat",
    "phone": "0999999999",
    "email": "employee01@kma.local",
    "role": "admin"
  }'
```

## SSRF internal test

```bash
curl -X POST http://localhost:8080/api/v1/tools/export-pdf \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_url":"http://kma-app:8000/health"}'
```

## View backend security metadata

```bash
tail -n 10 logs/app/app.log | jq '.security_metadata'
```

## View WAF access log

```bash
tail -n 20 logs/nginx/access.log
```

## View SIEM

```bash
docker logs kma-siem --tail=100
```

---

# 15. Mapping Summary

| Scenario                          | Endpoint                            | detected_attack                              | MITRE dự kiến |
| --------------------------------- | ----------------------------------- | -------------------------------------------- | ------------- |
| Failed login                      | `POST /auth/login`                  | `failed_login`                               | N/A           |
| JWT Forgery lab                   | `GET /auth/session/validate-lab`    | `jwt_unverified_validation`                  | `T1550.004`   |
| BOLA                              | `GET /api/v1/employees/{id}`        | `bola_attempt`                               | `T1190`       |
| Mass Assignment                   | `PATCH /api/v1/employees/profile`   | `mass_assignment_role_escalation`            | `T1078`       |
| SSRF internal                     | `POST /api/v1/tools/export-pdf`     | `ssrf_internal_request`                      | `T1190`       |
| Metadata SSRF blocked by backend  | `POST /api/v1/tools/export-pdf`     | `ssrf_metadata_request_blocked_by_lab_scope` | `T1190`       |
| Upload CV / RAG poisoning surface | `POST /api/v1/tools/upload-cv`      | `rag_poisoning_surface_access`               | `T1562`       |
| Admin log access                  | `GET /api/v1/admin/security-logs`   | `admin_log_access`                           | `T1059`       |
| AI-assisted RCE surface           | `POST /api/v1/admin/reboot-service` | `ai_assisted_rce_attempt`                    | `LLM02`       |
