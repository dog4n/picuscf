# Picus × Cloudflare WAF Platformu

Picus SCV web saldırı simülasyonlarını Cloudflare WAF loglarıyla eşleştirir; her koşumda neyin bloklandığını,
neyin geçtiğini, hangi kuralın kapattığını ve koşumlar arasındaki ilerlemeyi gösterir. Prod FP modülü, Block'a
alınacak kuralları prod trafiğindeki yanlış pozitif riskiyle birlikte değerlendirir.

Kodda hiçbir kuruma ait değer yoktur: token'lar yalnızca `.env` dosyasında, zone / test host'u / Picus IP'leri
Ayarlar sayfasında tutulur.

## Kurulum (Windows)

Gerekenler: Python 3.10+, [NSSM](https://nssm.cc) (servis için), yönetici PowerShell.

1. Zip'i bir klasöre açın (ör. Masaüstü).
2. O klasörde yönetici PowerShell açıp çalıştırın:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\kurulum.ps1 -Nssm "C:\Araclar\nssm.exe"
   ```
   Betik dosyaları `C:\PicusCF`'e kopyalar, sanal ortam kurar, `.env`'yi Not Defteri'nde açar (token'ları yapıştırıp
   kaydedin), servisi kurar ve sağlık kontrolü yapar. Güncellemede aynı komut yeterlidir; `data` ve `.env` korunur.
3. Tarayıcıda `http://localhost:9999` → ilk yönetici hesabını oluşturun → **Ayarlar**'da zone ID, test host'u ve
   Picus IP'lerini girip bağlantıyı test edin.

Parametreler: `-Hedef`, `-Port`, `-Python`, `-Nssm`, `-Name`, `-Proxy`, `-Disaridan` (varsayılan olarak uygulama
sadece sunucunun içinden açılır; `-Disaridan` HOST=0.0.0.0 yapar ve güvenlik duvarı kuralı ekler).

Linux/macOS: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && cp .env.example .env && .venv/bin/python run.py`

## Token yetkileri

- **Cloudflare** (`CF_API_TOKEN`): Zone → Analytics → Read. İsteğe bağlı: WAF okuma yetkisi — Prod FP'de her
  kuralın prod'daki gerçek durumunu (Log / Block / kapalı) gösterir. Token'da IP kısıtı varsa sunucunun internete
  çıkış IP'si izinli olmalı.
- **Picus** (`PICUS_API_TOKEN`, refresh token): okuma yetkileri. CSV raporunu API ile üretmek için
  `write:simulations` gerekir; yoksa uygulama threats/actions uç noktalarına düşer ya da Picus'ta elle üretilen
  raporun numarası koşuma girilerek yalnızca indirilir.

## Kullanım

- **Koşum**: Picus sonucu API'den (simülasyon + koşum seçimi) ya da CSV'den; Cloudflare logları API'den ya da CSV'den.
  Koşumlar Picus koşum tarihine göre sıralanır (koşum sayfasından düzeltilebilir).
- **Karşılaştır**: iki koşum arasında kapanan / açık kalan / gerileyen testler, kapanışın kaynağı (kural ailesi).
  CSV ve API kaynaklı koşumlar farklı kimlikler kullansa da testler otomatik eşleştirilir; eşleşme düşükse uyarı verir.
- **Değişiklikler**: Cloudflare'de yapılan değişiklikleri tarihleriyle kaydedin; trend grafiklerinde işaretlenir.
- **Otomatik çekme** (Ayarlar): izlenen Picus simülasyonlarının yeni koşumları otomatik çekilip analiz edilir.

## Prod FP ve kural kararları

| Karar | Anlamı |
|---|---|
| A | Doğrudan Block (Picus kazancı var, prod'da Log'da açık ve FP yok/çok az) |
| B | Exception ile Block (kazanç var, FP belirli host/path'lerde) |
| C | Prod'da kapalı kalsın (kazanç az, FP fazla) |
| D | Gerçek saldırı trafiği, Block önerilir (Picus dışı) |
| E | Meşru trafik ağırlıklı, kapalı kalsın (Picus dışı FP) |
| F | **Bilinen FP: Block'a alma** (Bilinen FP listesinde) |
| G | **Ölçülemedi: önce Log'da doğrula** (prod'da hiç olay yok ve kuralın açık olduğu doğrulanamadı) |

**Önemli:** Kapatılmış ya da skip'e alınmış bir kural Cloudflare'de hiç log üretmez. Prod'da "0 olay" görünen bir
kural bu yüzden "temiz" sayılmaz. FP nedeniyle kapattığınız kuralları **Bilinen FP** sayfasına ekleyin; Block'a
alacağınız listeyi aynı sayfadaki "Block listesini kontrol et" ile karşılaştırın.

Önerilen akış: kuralın prod'daki durumunu kontrol et → kapalıysa önce Log'da aç → 3–7 gün izle → Prod FP taraması →
kuralları birkaçar birkaçar Block'a al → "Uygulama durumu"nu güncelle → Değişiklikler'e kaydet.

## Güvenlik

Rol tabanlı giriş (Yönetici / İzleyici), CSRF koruması, sıkı CSP, giriş deneme sınırı, denetim kaydı.
Picus payload'ları saklanmaz (yalnızca istek satırı). Veritabanı: `data/picuscf.db`.

## Sorun giderme

- **Cloudflare "Authentication error" ama token doğru**: token'daki IP kısıtını ve sunucunun çıkış IP'sini kontrol edin.
- **Picus "invalid number of segments"**: `.env`'deki token eksik/yanlış yapıştırılmış.
- **Picus 403 (rapor)**: token'da `write:simulations` yok; rapor numarasıyla indirme yolunu kullanın.
- Servis logu: `C:\PicusCF\data\logs\servis.log`. Yönetim: `.venv\Scripts\python.exe manage.py` (yönetici oluştur,
  şifre sıfırla, bağlantı testi).
