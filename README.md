# North · Draw Loaders

مشروع Node/Express واحد يقدم:
- **`/`** و **`/loaders`** — صفحة العملاء لعرض المحمّلات وتحميلها بمفتاح.
- **`/auth`** — تسجيل دخول ولوحة تحكم كاملة (إدارة محمّلات، فريق، سجلات، إحصاءات).

يعمل على Railway مع Postgres وVolume للملفات.

## متطلبات البيئة (.env)

| المتغير | الوصف |
|---|---|
| `DATABASE_URL` | رابط Postgres (تلقائي على Railway) |
| `VOLUME_PATH` | مسار الـ Volume، افتراضي `/data` |
| `SESSION_SECRET` | سلسلة عشوائية طويلة لتوقيع الجلسات |
| `ADMIN_USERNAME` | مسؤول أساسي (افتراضي `North`) |
| `ADMIN_PASSWORD` | كلمة مروره (افتراضي `North123`) |
| `PORT` | افتراضي `8080` |

## التشغيل محليًا
```bash
npm install
DATABASE_URL=... VOLUME_PATH=./data node server.js
```

## النشر على Railway
- ارفع المستودع.
- أضف Postgres plugin — سيُحقن `DATABASE_URL` تلقائياً.
- أنشئ Volume واربطه بمسار `/data`.
- عيّن `SESSION_SECRET` قوي.
- افتح الدومين على المشروع.

## واجهات API الرئيسية
- عامة: `GET /api/public/loaders` — `GET /api/public/loaders/:id/image` — `POST /api/public/keys/check` — `GET /api/public/loaders/:id/download?key=...`
- إدارية (Bearer): `/api/loaders` (CRUD + reorder)، `/api/files/:kind`، `/api/admins`، `/api/stats`، `/api/downloads`، `/api/logs`.

المفتاح لا يُفعَّل ولا يُربط بـ HWID من هذا الموقع — فقط يُتحقق من صلاحيته لتمكين التحميل.
