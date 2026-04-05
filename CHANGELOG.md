# Changelog

كل التغييرات الملحوظة لبروتوكول Sibna موثَّقة هنا.

الصيغة مبنية على [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
المشروع يتبع [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.3] - 2026-04-05

### أمان — إصلاحات حرجة

- **F-01** `manager.rs`: إصلاح Race Condition في حلقة اكتشاف P2P — استُبدل نمط `contains_key + connect + insert` بـ `DashMap::entry().or_insert_with()` لإغلاق نافذة TOCTOU
- **F-02** `manager.rs`: إصلاح `unwrap_or_default()` على hex decode للـ peer ID — كان يُنتج ghost peers بمفتاح فارغ مشترك في الـ DashMap؛ الآن يُسجِّل `warn!` ويتخطى الـ peer

### أمان — إصلاحات عالية الخطورة

- **F-03** `manager.rs`: إضافة `MAX_ACTIVE_PEERS = 500` في `add_p2p_peer` وحلقة الاكتشاف — يمنع استنزاف الذاكرة عبر mDNS flood
- **F-04** `manager.rs`: `InternalErrorDetailed { details: e.to_string() }` استُبدل بـ `InternalError` في جميع نقاط الإرجاع العامة — التفاصيل في `warn!` الداخلي فقط
- **F-05** `manager.rs`: إضافة `Arc<tokio::sync::Notify>` + `stop_discovery()` + `tokio::select!` — حلقة الاكتشاف الآن قابلة للإيقاف النظيف

### أمان — إصلاحات متوسطة الخطورة

- **F-06** `manager.rs`: إضافة حارس `MAX_MESSAGE_BYTES = 64 MiB` في `send_message` قبل أي تخصيص ذاكرة
- **F-07** `manager.rs`: إضافة `is_valid_peer_addr()` — ترفض loopback / multicast / unspecified / port 0
- **F-08** `manager.rs`: استبدال التوزيع المنتظم بتوزيع أسي (Poisson process، متوسط 5 ثوانٍ) في cover traffic — يُصعِّب التعرف على الأنماط
- **N-01** `ws.rs`: استبدال `serde_json::to_vec(...).unwrap_or_default()` في موضعين بـ `match` صريح — يتجنب إرسال frame فارغ عند فشل التسلسل
- **N-02** `rate_limit.rs`: توثيق timing oracle المحتمل في `check()` (جزئي) — الإصلاح الكامل مؤجَّل لـ v1.1.0 (يتطلب إعادة هيكلة النوع)
- **N-03** `auth.rs`: تخزين `HMAC-SHA256(challenge, jwt_secret)` بدلاً من نص واضح في sled — يمنع استخراج challenges من قراءة ملفات قاعدة البيانات

### إضافات تبعيات

- `server/Cargo.toml`: إضافة `hmac = { workspace = true }` لدعم N-03

### توثيق

- `README.md`: تحديث شامل يعكس الميزات الفعلية والقيود الحقيقية
- `SECURITY.md`: إضافة جدول الحمايات المُطبَّقة والقيود الموثَّقة
- `PROTOCOL_SPECIFICATION.md`: توثيق `SignedEnvelope.signing_payload()` بدقة (تأكيد أن `is_dummy` مُضمَّن)
- `CONTRIBUTING.md`: إضافة قاعدة `InternalErrorDetailed` بأمثلة واضحة

---

## [1.0.1] - 2026-04-03

### إضافات

- **FFI كامل لدورة الجلسة**: إضافة `sibna_generate_identity`، `sibna_generate_prekey_bundle`، `sibna_perform_handshake`، `sibna_session_encrypt`، `sibna_session_decrypt` — يتيح استخدام X3DH والـ Double Ratchet من C/C++/Flutter/Python عبر FFI
- **Persistent Keystore**: إضافة `save_to_disk` و`load_from_disk` لـ `KeyStore` — تخزين مشفر بـ ChaCha20-Poly1305 عبر feature `persistent` (sled)
- **Ed25519 Challenge-Response**: إضافة `generate_challenge` و`verify_signed_challenge` للمصادقة التشفيرية الحقيقية
- **WASM Bindings**: إضافة `wasm.rs` يكشف دوال الجلسة/المصافحة لـ JavaScript/TypeScript عبر `wasm-bindgen`
- **Sibna Server**: crate جديدة تشغّل Axum HTTP server لرفع واسترجاع PreKeyBundle

### إصلاحات

- إصلاح خطأ compile في `IdentityKeyPair::from_bytes` (نوع مُرجَع خاطئ)
- إصلاح `lib.rs` لتحميل الهوية بتوقيع صحيح

---

## [0.9.0] - 2026-03-20

### أمان — إصلاحات حرجة

- **HKDF session init**: استبدال `expand()` مزدوج على نفس PRK بـ expand واحد 64-byte + split
- **QR code mac_key**: إزالة مفتاح MAC السري من حمولة QR المسلسلة (كان يُسرِّب مفتاح خاص)
- **كشف الـ shared secret**: `perform_handshake()` لم يعد يُرجع raw shared_secret للمستدعي
- **chain.rs derive_key**: إصلاح `?` operator مستخدم داخل دالة non-Result (كان يُسبب compile error / panic)
- **keystore::from_bytes**: تحويل من panic-on-error إلى `ProtocolResult<Self>`

### أمان — إصلاحات عالية الخطورة

- **Group DoS prevention**: إضافة حد `MAX_SKIP_GROUP=500` في `GroupSession::decrypt()`
- **Encryptor counter**: إصلاح `initial_message_number=u64::MAX` → `0` (كان يُعطِّل كشف الإعادة)
- **session.rs panics**: استبدال 4 استدعاءات `.unwrap()` في `skip_message_keys()` بـ `?`
- **add_group_member**: تمرير `ProtocolResult` من `add_member()` (كان يُتجاهَل بصمت)
- **builder.rs panic**: استبدال `SecureRandom::new().unwrap()` بمعالجة أخطاء صحيحة
- **constant_time_cmp**: توثيق أنها غير constant-time، وإخفاؤها من الـ Public API

### أمان — إصلاحات متوسطة الخطورة

- **MAX_AD_LEN**: توحيد حد التحقق (1024→256) مع حد طبقة التشفير
- **FFI last_error**: تطبيق تخزين thread-local للأخطاء (كان دائماً يُرجع رسالة عامة)
- **burst_tokens init**: إصلاح التهيئة من `100` → `0` (كان rate limiter غير فعّال ابتداءً)
- **X3DH HKDF salt**: استبدال `&[]` بثابت domain-separation
- **ملفات debug log**: إزالة 30 ملف `errors_v*.log` من المستودع

### تغييرات

- رفع الإصدار إلى 0.9.0
- `bincode`: استبدال RC version بـ stable `1.3.3`
- `aes-gcm`: إزالة (غير مستخدم، يزيد سطح الهجوم)
- اختبارات التكامل: إعادة كتابة كاملة بسيناريوهات واقعية

### إضافات

- `.github/workflows/ci.yml` — CI/CD مع security audit + Miri + اختبارات cross-platform
- `deny.toml` — سياسة cargo-deny (ترخيص + advisory + قواعد الحظر)
- `clippy.toml` — إعدادات clippy صارمة
- `rustfmt.toml` — تنسيق موحد
- `CONTRIBUTING.md` — إرشادات المساهمة ذات أولوية أمنية

---

## [0.8.0] - 2024-XX-XX

### أمان — إصلاحات حرجة

- **Memory Zeroization**: جميع البيانات الحساسة تُصفَّر عند الإسقاط عبر `zeroize`
- **Secure Serialization**: حالة الجلسة تُسلسَل الآن بصيغة binary مشفرة بدلاً من JSON
- **Key Storage**: مفاتيح الرسائل المتخطاة تُخزَّن مع انتهاء صلاحية تلقائي وتنظيف آمن

### أمان — إصلاحات عالية الخطورة

- **Input Validation**: تحقق شامل لجميع الـ APIs الخارجية
- **Rate Limiting**: حماية DoS لجميع عمليات التشفير
- **Timing Attack Prevention**: مقارنات constant-time في جميع المسارات
- **Authentication**: تقوية HMAC verification بمقارنة constant-time

---

## [7.0.0] - 2023-XX-XX

*(إصدار قديم — تفاصيل في git history)*
