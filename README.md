
```markdown
# Auth ve Token Yönetim Sistemi

Bu proje, kullanıcıların kayıt, giriş, çıkış ve token yönetimini sağlayan bir kimlik doğrulama sistemidir. Güvenlik özellikleri arasında refresh token blacklist mekanizması ve token geçersizlik kontrolleri bulunmaktadır.

## Özellikler
- Kullanıcı kayıt işlemleri.
- Kullanıcı giriş işlemleri.
- Access ve Refresh Token oluşturma.
- Cihaz bazlı oturum yönetimi.
- Blacklist mekanizması ile refresh token güvenliği.
- Global Exception Handler ile hata yönetimi.

---

## Endpoint Listesi

### 1. Kullanıcı Kayıt
- **Endpoint:** `/auth/register`
- **Method:** `POST`

#### Örnek Request:
```json
{
  "username": "testuser",
  "email": "testuser@example.com",
  "password": "StrongPassword123",
  "type": "CUSTOMER"
}
```

#### Örnek Response:
```json
{
  "message": "User registered successfully."
}
```

#### Hata Cevapları:
- **Kullanıcı adı veya email zaten mevcut:**
  ```json
  {
    "error": "Conflict",
    "message": "A user with this username or email already exists."
  }
  ```

- **Geçersiz kullanıcı tipi:**
  ```json
  {
    "error": "Bad Request",
    "message": "Invalid user type specified."
  }
  ```

---

### 2. Kullanıcı Giriş
- **Endpoint:** `/auth/login`
- **Method:** `POST`

#### Örnek Request:
```json
{
  "username": "testuser",
  "password": "StrongPassword123",
  "deviceName": "ChromeBrowser",
  "location": "Istanbul"
}
```

#### Örnek Response:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Hata Cevapları:
- **Geçersiz kullanıcı adı veya şifre:**
  ```json
  {
    "error": "Unauthorized",
    "message": "Invalid username or password."
  }
  ```

---

### 3. Logout (Cihaz Bazlı)
- **Endpoint:** `/auth/logout`
- **Method:** `POST`

#### Örnek Request:
```json
{
  "username": "testuser",
  "deviceName": "ChromeBrowser"
}
```

#### Örnek Response:
```json
{
  "message": "Logout successful."
}
```

#### Hata Cevapları:
- **Cihaz bulunamadı:**
  ```json
  {
    "error": "Internal Server Error",
    "message": "Device not found."
  }
  ```

---

### 4. Token Yenileme
- **Endpoint:** `/token/refresh`
- **Method:** `POST`

#### Headers:
```plaintext
Refresh-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Örnek Response:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Hata Cevapları:
- **Geçersiz veya süresi dolmuş token:**
  ```json
  {
    "error": "Unauthorized",
    "message": "Refresh token is invalid or expired."
  }
  ```

---

## Senaryolar

### Senaryo 1: Kullanıcı Kayıt
1. Kullanıcı `/auth/register` endpoint'ine istek atar.
2. Kullanıcı bilgileri doğrulanır ve veritabanına kaydedilir.
3. Başarılı bir kayıt mesajı döner.

### Senaryo 2: Kullanıcı Giriş
1. Kullanıcı `/auth/login` endpoint'ine istek atar.
2. Kullanıcı adı ve şifre doğrulanır.
3. Cihaz bilgileri güncellenir veya kaydedilir.
4. Access ve Refresh Token döner.

### Senaryo 3: Logout (Cihaz Bazlı)
1. Kullanıcı belirli bir cihazdan çıkış yapmak için `/auth/logout` endpoint'ine istek atar.
2. Refresh token blacklist'e eklenir.
3. Cihaz bilgileri kaldırılır.

### Senaryo 4: Token Yenileme
1. Kullanıcı geçerli bir refresh token ile `/token/refresh` endpoint'ine istek atar.
2. Refresh token doğrulanır ve yeni bir access token döner.

---

## Hata Yönetimi

Global Exception Handler ile merkezi hata yönetimi sağlanmıştır.

#### Örnek Hata Cevabı:
```json
{
  "status": 400,
  "message": "Invalid user type specified.",
  "error": "Bad Request",
  "timestamp": "2024-11-20T08:00:00.000Z"
}
```

---

## Postman Kullanımı

1. **Yeni Kullanıcı Kayıt:**
    - **Endpoint:** `/auth/register`
    - **Method:** `POST`
    - **Body:** Kullanıcı bilgileri.

2. **Kullanıcı Girişi:**
    - **Endpoint:** `/auth/login`
    - **Method:** `POST`
    - **Body:** Kullanıcı bilgileri ve cihaz bilgileri.

3. **Logout İşlemi:**
    - **Endpoint:** `/auth/logout`
    - **Method:** `POST`
    - **Body:** Kullanıcı adı ve cihaz adı.

4. **Token Yenileme:**
    - **Endpoint:** `/token/refresh`
    - **Method:** `POST`
    - **Header:** Refresh-Token.

---

## Geliştirme Notları
- **TokenEncryptionService:** Refresh token'ları şifrelemek ve çözmek için kullanılır.
- **Blacklist Mekanizması:** Refresh token blacklist kontrolü ile güvenlik sağlanır.
- **Cihaz Yönetimi:** Kullanıcı cihaz bilgileri `DeviceService` ile yönetilir.
```

