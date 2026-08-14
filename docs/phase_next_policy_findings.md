# نتائج مراجعة المرحلة التالية

تاريخ المراجعة: 2026-08-15

## Google Play وصلاحيات الرسائل

المصدر الرسمي: [Use of SMS or Call Log permission groups](https://support.google.com/googleplay/android-developer/answer/10208820?hl=en)

تقيّد Google Play صلاحيات SMS وCall Log عالية الحساسية. الاستخدامات الأساسية المسموح بها ترتبط عادةً بتطبيق SMS أو Phone أو Assistant الافتراضي، ويجب أن يكون التطبيق مسجّلًا فعليًا كالمعالج الافتراضي قبل طلب الصلاحية. تذكر السياسة استثناءً مؤقتًا لمكافحة SMS phishing/smishing، لكنه يتطلب سجلًا موثقًا لحماية عدد مهم من المستخدمين مدعومًا بتقارير محللين أو نتائج اختبارات معيارية أو منشورات موثوقة، مع مراجعة Google Play.

القرار الهندسي: لا نضيف READ_SMS أو RECEIVE_SMS في الإصدار التالي. نستخدم فحصًا صريحًا عبر مشاركة الرسالة أو النص إلى Aman، ونستفيد من استخراج الروابط والمؤشرات محليًا. هذا يحافظ على الخصوصية ويقلل احتمال رفض Google Play.

## متطلبات target API

المصدر الرسمي: [Meet Google Play's target API level requirement](https://developer.android.com/google/play/requirements/target-sdk)

ابتداءً من 31 أغسطس 2026 يجب أن تستهدف التطبيقات الجديدة وتحديثاتها Android 16 / API 36 أو أعلى للتقديم إلى Google Play. المشروع الحالي مضبوط على compileSdk 36 وtargetSdk 36، ولذلك يحقق هذا الشرط الحالي للمواعيد المذكورة في المصدر.

## تصميم المرحلة

- حماية الروابط: توسيع الفحص المحلي وواجهة التحذير، مع إبقاء قرار الفتح للمستخدم في الحالات غير الآمنة.
- الرسائل: مشاركة صريحة للنص أو الرابط؛ لا قراءة تلقائية للرسائل ولا إرسالها خارج الجهاز.
- التطبيقات: الاستفادة من InstalledAppScanner وPackageManager الحاليين، مع إبراز مؤشرات accessibility/overlay/install packages ومصدر التثبيت بدل ادعاء اكتشاف كل العمليات الخفية.
- البطارية: قراءة محلية محدودة من UsageStats/بطارية النظام إن أمكن، مع تجنب خدمة دائمة أو polling كثيف، وعرض تنبيه إرشادي لا حكمًا قطعيًا بالبرمجية الخبيثة.
- Play: مراجعة الصلاحيات، Data safety، وصف الوظائف، target API، والتوقيع/الإصدار، ثم بناء AAB قابل للمراجعة دون نشر تلقائي.

## تحديث المصادر الرسمية في 2026-08-15

- **Target API:** صفحة Android Developers تنص على أنه ابتداءً من 31 أغسطس 2026 يجب أن تستهدف التطبيقات الجديدة وتحديثاتها Android 16 / API 36 أو أعلى للتقديم إلى Google Play. إعداد المشروع الحالي `targetSdk 36`، ويجب إبقاءه محدثًا عند بناء 3.5.9. المصدر: [Meet Google Play's target API level requirement](https://developer.android.com/google/play/requirements/target-sdk).
- **SMS/Call Log:** Google Play يقيّد صلاحيات SMS وسجل المكالمات، ويطلب إزالة الصلاحيات من التطبيقات غير المؤهلة أو تقديم Permissions Declaration Form عند وجود استخدام مسموح. لذلك يبقى فحص الرسائل في Aman عبر مشاركة صريحة محلية، دون `READ_SMS` أو `RECEIVE_SMS` أو `READ_CALL_LOG`. المصدر: [Use of SMS or Call Log permission groups](https://support.google.com/googleplay/android-developer/answer/10208820?hl=en).
- **Data safety:** يجب على كل تطبيق منشور إكمال نموذج Data safety، بما في ذلك التطبيقات في مسارات الاختبار المغلقة والمفتوحة والإنتاج؛ والتطبيقات التي لا تجمع بيانات مطالبة أيضًا بإكمال النموذج وتوفير رابط سياسة الخصوصية. يجب أن تعكس الإجابات سلوك التطبيق الفعلي وأي مكتبات خارجية. المصدر: [Provide information for Google Play's Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en-GB).
- **Signing:** يتطلب Google Play رفع AAB موقّعًا بمفتاح upload key، ثم يتولى Play App Signing توقيع APKs الموزعة. حزمة AAB الحالية الناتجة من CI غير موقعة للنشر، ولذلك لا تُرفع إلى Play Console قبل ربط إعداد توقيع آمن عبر أسرار GitHub أو بيئة المستخدم. المصدر: [Sign your app](https://developer.android.com/studio/publish/app-signing).

### نتيجة تدقيق أولية

| البند | الحالة في Aman 3.5.9 | الإجراء المطلوب قبل النشر |
|---|---|---|
| target API | جاهز: targetSdk 36 | التحقق من سلوك Android 16 على جهاز/محاكي |
| SMS permissions | مناسب: لا توجد صلاحيات SMS/Call Log | إبقاء الفحص عبر Share/Process Text فقط |
| Data safety | يحتاج تعبئة في Play Console | مراجعة السلوك الفعلي والمكتبات ثم إدخال النموذج |
| Privacy policy | يحتاج رابطًا عامًا صالحًا في Play Console | توفير صفحة سياسة خصوصية عامة |
| AAB signing | يحتاج إعداد upload key | توقيع release AAB بمفتاح لا يُرسل عبر المحادثة |
| Sensitive permissions | `MANAGE_EXTERNAL_STORAGE` و`QUERY_ALL_PACKAGES` موجودتان لوظائف الحماية الحالية | مراجعة إفصاحات Play وتقديم declaration عند طلبها |
