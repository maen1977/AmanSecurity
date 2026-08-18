# Maen Shield 1.1.1.5

## العربية

- إصلاح تصنيف ملفات ZIP والأرشيفات العادية أثناء Full scan.
- تجاوز حدود فحص الأرشيف أو وجود مؤشر امتداد مضلل أصبح يظهر كـ «يحتاج إلى مراجعة» بدل «High-risk security alert»، ما لم توجد بصمة تهديد معروفة أو دليل قوي على ملف APK ضار.
- عدم زيادة عداد التهديدات أو إرسال إشعار High-risk بسبب ملف ZIP غير مؤكد.
- استمرار عرض الملفات التي تحتاج إلى مراجعة داخل نتائج الفحص مع توضيح أنها ليست برمجية خبيثة مؤكدة.
- إبطال نتائج cache القديمة التي كانت تحفظ بعض الأرشيفات كعالية الخطورة.
- التهديدات المعروفة المؤكدة ومؤشرات APK القوية تبقى تنبيهات عالية الأولوية ولا يتم كتمها.
- الحفاظ على الفحص المحلي الخفيف ودعم Android 8.0 / API 26 وما بعده.

ساهم Manus AI في تحليل المشكلة، مراجعة مسارات الفحص، وتصميم الإصلاح واختباره.

## English

- Fixed Full scan classification of ordinary ZIP and archive files.
- Archive scan limits and misleading-extension signals are now shown as “Needs review” instead of “High-risk security alert” unless a known threat signature or strong APK evidence is present.
- Unconfirmed ZIP findings no longer increase the threat counter or emit a High-risk notification.
- Review-only files remain visible in scan results with an explicit non-malware wording.
- Invalidated old scan-cache entries that could preserve a previous High-risk archive classification.
- Confirmed known threats and strong APK evidence remain high-priority alerts and are never suppressed.
- Preserved the lightweight local design and Android 8.0 / API 26 compatibility.

Manus AI contributed to the issue analysis, scan-path review, fix design, and validation.
