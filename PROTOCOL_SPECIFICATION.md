# مواصفات بروتوكول Sibna — v1.0.3

---

## 1. اتفاقية المفاتيح: X3DH

### 1.1 أنواع المفاتيح

| النوع | الخوارزمية | العمر |
|-------|------------|-------|
| Identity Key (IK) | Ed25519 / X25519 | دائم |
| Signed Prekey (SPK) | X25519 موقَّع بـ IK | متوسط (قابل للتجديد) |
| One-Time Prekey (OPK) | X25519 | استخدام واحد |
| Ephemeral Key (EK) | X25519 | جلسة واحدة |

### 1.2 اشتقاق المفاتيح

الـ shared secret يُشتق من أربع عمليات Diffie-Hellman (DH1–DH4) مدمجة عبر HKDF-SHA256. يُطبَّق domain separation باستخدام ثوابت خاصة بالإصدار (`SibnaX3DH_SessionKeys_v9`).

### 1.3 الهجين الكمي (افتراضي: مفعَّل)

كل handshake يدمج آليتين مستقلتين:

1. **X25519**: Diffie-Hellman الكلاسيكي
2. **ML-KEM-768** (CRYSTALS-Kyber، FIPS 203): الطرف المبادر يُغلف سراً ضد مفتاح KEM للطرف المستجيب

**دمج المفاتيح:** يُدمج الـ shared secret الكلاسيكي والكمي بالتسلسل قبل تمريرهما لـ HKDF. يجب كسر **كلاهما** في آنٍ واحد للاختراق.

> ⚠️ بدون `pqc` feature: X25519 فقط — عرضة لخوارزمية Shor.

---

## 2. إدارة الجلسات: Double Ratchet

### 2.1 Symmetric Ratchet

كل رسالة تُشفَّر بمفتاح فريد مشتق من chain key. يُحدَّث الـ chain key عبر HMAC-SHA256 بعد كل رسالة (Forward Secrecy).

### 2.2 DH Ratchet

يوفر Post-Compromise Security. يُجرَى بعد كل جولة كاملة لإعادة ضبط حالة الأمان.

---

## 3. التوجيه الهجين (P2P + Relay)

### 3.1 `HybridRouter` — سياسة "P2P أولاً"

```
send_message(recipient, plaintext)
    │
    ├─ [P2P متاح؟] ──→ جلسة نشطة في active_peers?
    │                      ├─ نعم ──→ peer.send_message()
    │                      │              ├─ نجح ──→ return Ok
    │                      │              └─ فشل ──→ warn + fallback
    │                      └─ لا ──→ fallback
    │
    └─ send_via_relay(recipient, plaintext)
           └─ encrypt_message() → log → Ok
```

### 3.2 حدود الأمان في HybridRouter

| الحد | القيمة | الهدف |
|------|--------|-------|
| `MAX_ACTIVE_PEERS` | 500 | منع استنزاف الذاكرة عبر mDNS flood |
| `MAX_MESSAGE_BYTES` | 64 MiB | منع تخصيص ذاكرة ضخمة |
| تحقق العنوان | رفض loopback / multicast / unspecified / port 0 | منع الاتصال بعناوين غير صالحة |
| Cover Traffic | توزيع أسي، متوسط 5 ثوانٍ | إخفاء أنماط النشاط |

### 3.3 اكتشاف P2P (mDNS)

- يعمل في حلقة background task مع `tokio::select!` على cancellation token
- يُوقَف نظيفاً عبر `stop_discovery()`
- يرفض peer_id غير صالح (hex decode فاشل أو نتيجة فارغة)
- يُطبِّق TOCTOU-safe connect عبر `DashMap::entry().or_insert_with()`

---

## 4. Sealed Sender

الخادم يُوجِّه مغلَّفات مختومة دون معرفة هوية المُرسِل. كل مغلَّف `SignedEnvelope` موقَّع بـ Ed25519 على SHA-512 من الحقول التالية مدمجةً:

```
SHA-512(recipient_id ∥ payload_hex ∥ timestamp_le ∥ message_id ∥ is_dummy)
```

حقل `is_dummy` مُدرَج في التوقيع — يمنع الخادم من تحويل رسالة حقيقية إلى رسالة وهمية أو العكس.

---

## 5. إخفاء حجم الرسالة (Padding)

| الوضع | حجم الكتلة | الاستخدام |
|-------|------------|-----------|
| `None` | بلا padding | غير موصى به |
| `Small` | 256 B | IoT / أجهزة محدودة |
| `Standard` (افتراضي) | 1 KB | الرسائل العامة |
| `Large` | 4 KB | نقل الملفات |
| `Maximum` | 16 KB | أقصى حماية من تحليل الحجم |
| `Custom(n)` | n bytes | مطورون متقدمون |

**الصيغة:** `[ plaintext | random_padding | 2-byte LE padding_len ]`

---

## 6. المعاملات التشفيرية

| المعامل | الخوارزمية |
|---------|-----------|
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| Key Exchange | X25519 (+ ML-KEM-768 افتراضياً) |
| التوقيع | Ed25519 |
| Post-Quantum KEM | ML-KEM-768 (FIPS 203) |
| تجزئة المغلَّفات | SHA-512 |
| HMAC (Auth challenges) | HMAC-SHA256 |
| Randomness | OS CSPRNG عبر `getrandom` |
| المقارنة الثابتة الزمن | `subtle` crate |

---

## 7. إدارة الذاكرة

جميع البنى الحساسة (مفاتيح خاصة، shared secrets، chain keys) تُطبِّق `ZeroizeOnDrop`. تُكتَب البيانات بالأصفار عند إسقاط الكائن.

---

## 8. مصادقة الخادم (JWT + Ed25519 Challenge-Response)

1. العميل يطلب challenge عشوائي (32 byte)
2. الخادم يخزن `HMAC-SHA256(challenge, jwt_secret)` في sled — ليس النص الواضح
3. العميل يوقّع الـ challenge بمفتاح Ed25519 الخاص به
4. الخادم يتحقق من التوقيع + HMAC integrity ثم يُصدر JWT صالح 24 ساعة
5. الـ challenge يُحذف فور الاستخدام (one-time use)

---

## 9. خارج نطاق البروتوكول

| الخاصية | الحالة | الملاحظة |
|---------|--------|----------|
| حماية الـ metadata العميقة | ⚠️ جزئي | padding يخفي الحجم، الـ IP والتوقيت مرئيان بدون Tor |
| إخفاء الهوية | ⚠️ جزئي | عبر `proxy` فقط (SOCKS5/Tor) |
| منع MITM الآلي | ⚠️ جزئي | تثبيت المفاتيح يحمي من التغيير اللاحق، لكن TOFU يسري على الاتصال الأول |
| أمان طبقة النقل | ❌ غير مُوفَّر | التطبيق مسؤول عن TLS أو ما يعادله |
