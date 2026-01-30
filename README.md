# Hrithik.Security.ReplayProtection

Enterprise-grade **Replay Attack Protection** for .NET APIs.  
Specially designed for **Banking, Fintech, and secure distributed systems**.

---

## ❓ What is a Replay Attack?

Jab koi attacker ek valid API request ko copy karke  
use **dubara server par bhej deta hai**, usse Replay Attack kehte hain.

Ye especially dangerous hota hai:
- Banking APIs
- Payment systems
- Secure transactions

---

## ✅ What does this library do?

- Validates **Nonce + Timestamp**
- Prevents duplicate requests (replay attacks)
- Supports **distributed systems**
- Works with **ASP.NET Core**
- Cloud-ready (Redis / Distributed Cache)

---

## 🚀 Quick Start

### 1️⃣ Register services

services.AddReplayProtection(options =>
{
    options.AllowedClockSkew = TimeSpan.FromMinutes(5);
});

2️⃣ Add middleware
app.UseReplayProtection();

📩 Required Request Headers

Every protected request must include:

X-Request-Id   → Unique nonce (UUID recommended)
X-Timestamp    → Unix timestamp (UTC, seconds)


Example:

X-Request-Id: 550e8400-e29b-41d4-a716-446655440000
X-Timestamp: 1738231456



🔐 Security Note (IMPORTANT)


This library prevents replay attacks only.

It does NOT:

Authenticate callers

Authorize requests

Validate request signatures

Use it together with:

JWT / OAuth / mTLS

Request signing (HMAC / RSA)



🧱 Production Usage (Redis)

For distributed systems, use IDistributedCache (Redis):

services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = "localhost:6379";
});

services.AddSingleton<INonceStore, DistributedCacheNonceStore>();
