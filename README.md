# Sibna Protocol

تطبيق Rust لبروتوكول X3DH والـ Double Ratchet — تشفير E2EE مرخّص Apache 2.0 / MIT.

---

> **ملاحظة**: هذا مشروع مستقل. غير تابع لـ Signal Technology Foundation ولا Signal Messenger ولا يستخدم كودهم.

---

## نظرة عامة

Sibna مكتبة تشفير توفر تطبيقاً مستقلاً لبروتوكول Signal-style E2EE. مصمم للتكامل مع تطبيقات تجارية أو مفتوحة المصدر حيث ترخيص GPLv3 أو البنية التحتية الرسمية لـ Signal غير ملائمة.

| الميزة | الحالة | التفاصيل |
|--------|--------|----------|
| **سرية الرسائل** | ✅ مدعوم | ChaCha20-Poly1305 AEAD |
| **Forward Secrecy** | ✅ مدعوم | رatchet متماثل يُجدد المفتاح مع كل رسالة |
| **Post-Compromise Security** | ✅ مدعوم | DH ratchet يُعيد التهيئة بعد كل جولة |
| **مقاومة الكم (افتراضي)** | ✅ مدعوم | هجين X25519 + ML-KEM-768 (FIPS 203) |
| **إخفاء حجم الرسالة** | ✅ مدعوم | padding بكتل ثابتة (256 B → 16 KB) |
| **Cover Traffic** | ✅ مدعوم | توزيع أسي (Poisson) — F-08 |
| **مصادقة P2P** | ✅ مدعوم | X3DH مباشر عبر TCP |
| **Relay مُشفَّر** | ✅ مدعوم | WebSocket + Sealed Sender (الخادم لا يرى المُرسِل) |
| **SOCKS5 / Tor** | ✅ مدعوم | `P2pConfig::proxy` أو `RelayClient::new(url, Some(proxy))` |
| **رسائل المجموعات** | ✅ مدعوم | Sender Key pattern |
| **FFI (C/Flutter/Python)** | ✅ مدعوم | `core/src/ffi/mod.rs` |
| **WASM** | ✅ مدعوم | `core/src/wasm.rs` |

## البدء السريع (Rust)

```rust
use sibna_core::{SecureContext, Config};
use sibna_core::crypto::{CryptoHandler, KeyGenerator};

// 1. تهيئة السياق
let config = Config::default();
let ctx = SecureContext::new(config, Some(b"SecurePass123!"))?;

// 2. توليد الهوية
let identity = ctx.generate_identity()?;

// 3. تشفير وفك تشفير
let key     = KeyGenerator::generate_key()?;
let handler = CryptoHandler::new(key.as_ref())?;

let ciphertext = handler.encrypt(b"Hello world", b"aad")?;
let plaintext  = handler.decrypt(&ciphertext, b"aad")?;
```

## التوجيه الهجين (P2P + Relay)

`HybridRouter` ينفذ سياسة "P2P أولاً":

1. يحاول الاتصال المباشر عبر P2P إذا توفّر جلسة نشطة
2. يتحوّل تلقائياً إلى Relay إذا فشل P2P
3. يدعم اكتشاف الأجهزة المحلية عبر mDNS

```rust
let mut router = HybridRouter::new(ctx);

// اختياري: تفعيل P2P
let node = P2pNode::new(P2pConfig::default(), ctx2).await?;
router.set_p2p_node(node);
router.start_discovery_loop().await?;

// اختياري: Cover Traffic (توزيع أسي، متوسط 5 ثوانٍ)
router.set_cover_traffic(true);
router.start_cover_traffic_loop(2, 30);

// إرسال رسالة (P2P أو Relay تلقائياً)
router.send_message(&recipient_id, b"Hello").await?;

// إيقاف نظيف
router.stop_discovery();
```

## حدود الأمان (اقرأها)

> [!CAUTION]
> هذه قيود معمارية وليست أخطاء. المطوّرون مسؤولون عن معالجتها.

| القيد | التوضيح |
|-------|---------|
| **TOFU** | التبادل الأول عرضة لـ MITM. يجب التحقق من "Safety Numbers" خارج النطاق للتأكيد المطلق |
| **GPA** | لا حماية كاملة من مراقب يرى الشبكة الكاملة (Global Passive Adversary) |
| **Anonymity** | إخفاء الهوية متاح فقط عبر Tor (`proxy = Some("socks5://127.0.0.1:9050")`) |
| **Transport Security** | المكتبة لا توفر TLS — التطبيق مسؤول عن تأمين الطبقة التحتية |
| **Side Channels** | نستخدم `subtle` لمقاومة timing attacks لكن لا ضمان ضد Spectre/Meltdown |

## حالة المشروع: v1.0.3

- **التحقق الآلي**: مجموعة 12 اختباراً أمنياً (attack vectors)
- **لا تدقيق خارجي**: لم تُجرَ مراجعة أمنية مستقلة خارجية حتى الآن
- راجع [SECURITY.md](SECURITY.md) و[PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md)

## الترخيص

Apache License 2.0 / MIT (مزدوج — اختر ما يناسبك)
