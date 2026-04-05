# المساهمة في Sibna Protocol

## الأمان أولاً

هذه مكتبة تشفير. كل مساهمة يجب أن تتبع هذه القواعد:

### القواعد الحرجة

- **لا `.unwrap()` أو `.expect()` في كود الإنتاج** — استخدم `?` أو معالجة أخطاء صريحة
- **لا تبعيات جديدة بدون مراجعة أمنية** — شغّل `cargo audit` قبل إضافة أي crate
- **لا primitives تشفير مخصصة** — استخدم فقط crates مُدقَّقة من RustCrypto
- **كل Public API يجب توثيقه** — مطلوب ملاحظات أمنية للدوال التشفيرية
- **جميع الاختبارات يجب أن تنجح** بما فيها `cargo clippy -- -D warnings`

### قاعدة `InternalErrorDetailed`

يُسمح باستخدام `ProtocolError::InternalErrorDetailed { details }` **فقط** لأغراض التسجيل الداخلي (`warn!` / `error!`). يجب **عدم إرجاعه** إلى المستدعي الخارجي. استخدم `ProtocolError::InternalError` للقيمة المُرجَعة العامة.

```rust
// ✅ صحيح
.map_err(|e| {
    warn!("OPERATION_FAILED: {:?}", e);   // تفاصيل في السجل فقط
    ProtocolError::InternalError          // عام للمستدعي
})?;

// ❌ خطأ
.map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;
```

### إرسال التغييرات

1. Fork المستودع وأنشئ feature branch
2. شغّل مجموعة الاختبارات الكاملة: `cargo test --all`
3. شغّل Clippy: `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used`
4. شغّل التنسيق: `cargo fmt --all`
5. شغّل التدقيق الأمني: `cargo audit`
6. أرسل pull request مع وصف واضح

### الإبلاغ عن الثغرات

**لا تفتح issues عامة للثغرات الأمنية.**

📧 `security@sibna.dev`

### قواعد السلوك

احترام وبناء. بحث الأمان يفيد الجميع.
