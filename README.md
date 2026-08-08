# 🛡️ vigil

![GitHub release (latest by date)](https://img.shields.io/github/v/release/resul-e/vigil)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Downloads](https://img.shields.io/github/downloads/resul-e/vigil/total?style=flat-square&color=orange)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-b7410e)
![License](https://img.shields.io/badge/license-MIT-green)

[🇹🇷 Türkçe](#-türkçe) | [🇬🇧 English](#-english)

---

## <a id="türkçe"></a>🇹🇷 Türkçe

vigil, Türkiye'deki erişim engellerini (DPI) aşan, Rust ile yazılmış hafif bir masaüstü aracıdır.
**Sürücü kurmaz, yönetici yetkisi istemez, kurulum yapmaz.** Tek klasör, birkaç dosya; silersen
geriye hiçbir şey kalmaz.

### 🚀 Kurulum

1. **İndirin:** [Releases](https://github.com/resul-e/vigil/releases) sayfasından **"Latest"**
   etiketli sürümdeki `vigil-vX.X.X-windows.zip` dosyasını indirin.
2. **Çıkartın:** ZIP'i bir klasöre çıkartın. Masaüstü olur, başka bir yer de olur.
3. **Dosyaları kontrol edin:**
   * `vigil-app.exe` — ana program (masaüstü sürümü)
   * `vigil.exe` — aynı motor, komut satırında
   * `vigil-repair.exe` — **acil durum aracı**
4. **Çalıştırın:** `vigil-app.exe`'ye çift tıklayın. Sağ altta, saatin yanında bir kalkan simgesi
   çıkar.
5. **Açın:** Simgeye **sağ tıklayın → "Korumayı aç"**.

> **⚠️ `vigil-repair.exe`'yi silmeyin.** Program yarım kapanırsa Windows'un proxy ayarı artık
> çalışmayan bir programı gösteriyor olabilir ve internet gitmiş gibi görünür. O dosyaya çift
> tıklamak her şeyi geri alır. Aynı klasörde dursun.

> **Windows "bilgisayarınızı korudu" derse:** program imzalı olmadığı için. **Daha fazla bilgi →
> Yine de çalıştır.** Kaynak kodun tamamı bu depoda; isterseniz kendiniz derleyin.

### 🔌 Programları bağladıktan sonra yeniden başlatın

"Korumayı aç" dediğiniz an vigil, Windows'un proxy ayarını ve `HTTPS_PROXY` değişkenlerini kendine
yönlendirir. Ama **programlar bu ayarı sadece açılırken bir kez okur.** Yani korumayı açmadan önce
çalışan bir Discord eski ayarla kalır.

**Doğru sıra:** vigil-app.exe → Korumayı aç → *sonra* uygulamayı aç.

### 🧠 Ne yapıyor?

Engelleme, TLS el sıkışmasının ilk paketindeki site adını (SNI) görerek çalışıyor. vigil o paketi
yeniden çerçeveliyor: hem daha küçük TLS kayıtlarına bölüyor, hem de ilk baytını ayrı gönderiyor.
Engelleyen cihaz site adını bir arada göremediği için tanıyamıyor.

Trafiğin geri kalanına **dokunmuyor** — bağlantı kurulduktan sonra veri olduğu gibi akıyor,
hız kaybı yok.

**Hangi yöntemin işe yaradığı hatta göre değişiyor**, ve vigil bunu site site kendisi öğreniyor:

| | Türk Telekom (AS9121) | Turkcell Superonline (AS34984) |
|---|---|---|
| Engelleme şekli | RST enjeksiyonu, ~2 ms | Sessiz düşürme, 6 sn |
| İlk baytı ayırmak (`split:1`) | **20/20** | **0/10** — hatta RST'ye çeviriyor |
| TLS kayıt bölme (`tlsrec:64`) | 10/10 | **10/10** |
| Varsayılan (`tlsrec:64+split:1`) | 10/10 | 10/10 |

Yani tek bir ülke ayarı yok. **Otomatik mod** her site için doğru yöntemi deneyip öğreniyor ve
hatırlıyor.

### 📊 Ölçüm

Ölçülen sonuçlar, aynı anda aynı hatta, doğrudan bağlantı ile vigil üzerinden karşılaştırmalı:

```
Türk Telekom (AS9121)              doğrudan     vigil'den
  discord.com                        0/6          6/6
  updates.discord.com                0/6          6/6
  gateway.discord.gg                 0/6          6/6
  roblox.com  (+6 alt alan adı)      0/6          6/6
  4chan.org                          0/5          5/5
  example.com          (kontrol)     6/6          6/6

Turkcell Superonline (AS34984)     doğrudan     vigil'den
  engellenen 10 alan adı             0/6          6/6      (60/60)
```

Hız, doğrudan bağlantıyla aynı seviyede: **80.8 MB/s** (vigil) — **78.2 MB/s** (doğrudan).

### 🖱️ Menüde ne var?

| | |
|---|---|
| **Korumayı aç / kapat** | Sistem proxy'si + `HTTPS_PROXY` |
| **Mod** | otomatik *(önerilen)* · `tlsrec:64+split:1` · `split:1` · `tlsrec:64` · dokunma |
| **DNS'i de vigil'e ver** | Yönetici izni sorar. Proxy ayarını okumayan programlar için |
| **Windows ile başlat** | İsteğe bağlı |
| **Ayrıntılar…** | Sayaçlar ve her site için öğrenilmiş yöntem |

### 🌐 DNS

Bazı hatlarda sağlayıcı, engelli adları **yanlış adrese çözüyor** (ölçüldü: `discord.com` →
`195.175.254.2`, engelleme sayfası). vigil kendi çözümleyicisini kullandığı için proxy'den geçen
her şey bundan etkilenmiyor.

**"DNS'i de vigil'e ver"** seçeneği bunu proxy'yi hiç kullanmayan programlar için de düzeltir.
Tek yönetici izni isteyen işlem budur, çünkü Windows'un ağ ayarına yazar. Kapanırken geri alır ve
arkasına her zaman bir yedek çözümleyici (`9.9.9.9`) yazar, böylece vigil kapansa bile makine
isim çözmeye devam eder.

### ❓ Sıkça sorulan sorular

* **İnternetim gitti, siteler açılmıyor.** `vigil-repair.exe`'ye çift tıklayın. Ayarları geri alır.
* **Discord/Roblox hâlâ açılmıyor.** Korumayı açtıktan **sonra** uygulamayı yeniden başlattınız mı?
  Ortam değişkenleri süreç başlarken okunuyor.
* **Discord'da sesli sohbet çalışmıyor.** Ses UDP üzerinden gidiyor; bir proxy bunu taşıyamaz.
  Bilinen sınır.
* **Yavaşlatır mı?** Hayır. Sadece ilk paket değiştiriliyor, gerisi olduğu gibi akıyor.
* **Bankam / e-Devlet etkilenir mi?** Hayır. `*.gov.tr` ve Türk bankaları varsayılan olarak
  listede hariç tutulmuş, onlara hiç dokunulmuyor.
* **Kapatınca ayarlar geri gelir mi?** Evet — çıkışta, Ctrl-C'de, ve bilgisayar kapanırken.

### 🔨 Kaynaktan derleme

```bash
git clone https://github.com/resul-e/vigil
cd vigil
cargo test --workspace                 # testler Linux'ta da çalışır
cargo build --release --target x86_64-pc-windows-msvc
```

Çekirdek mantık (`core/`) **sıfır bağımlılıklı** ve saf: bayt girer, bayt çıkar. İşletim sistemine
dokunan her şey `platform/` içinde ve incedir.

### 🔮 Yol haritası

* [ ] **Otomatik güncelleme** — bütün dosyaları, sansürlü hattın kendisi üzerinden
* [ ] **Açılışta devrede başlama** — şu an "Windows ile başlat" programı açıyor, korumayı değil
* [ ] **macOS sürümü** — kodun ~%90'ı zaten taşınabilir
* [ ] **CI ile şeffaf derleme** — GitHub Actions, imzalı sürümler

---

## <a id="english"></a>🇬🇧 English

vigil is a lightweight Windows desktop tool, written in Rust, that gets past DPI-based internet
blocking in Turkey. **No driver, no administrator rights, no installation.** One folder, a few
files; delete it and nothing is left behind.

### 🚀 Installation

1. **Download** `vigil-vX.X.X-windows.zip` from the **"Latest"** release on the
   [Releases](https://github.com/resul-e/vigil/releases) page.
2. **Extract** it anywhere.
3. **Check the files:**
   * `vigil-app.exe` — the main program (desktop version)
   * `vigil.exe` — the same engine on the command line
   * `vigil-repair.exe` — **the emergency tool**
4. **Run** `vigil-app.exe`. A shield icon appears in the system tray.
5. **Turn it on:** right-click the icon → **"Korumayı aç"** (turn protection on).

> **⚠️ Do not delete `vigil-repair.exe`.** If the program is killed rather than closed, Windows may
> still point at a proxy that is no longer running and it will look like your internet is gone.
> Double-clicking that file undoes everything. Keep it in the same folder.

> **If Windows says "Windows protected your PC":** the binaries are unsigned. **More info → Run
> anyway.** All source is in this repository if you would rather build it yourself.

### 🔌 Restart applications after turning protection on

Turning protection on points Windows' proxy setting and the `HTTPS_PROXY` environment variables at
vigil. But **programs read those once, at startup.** A Discord that was already running keeps the
old settings.

**Correct order:** vigil-app.exe → turn protection on → *then* start the application.

### 🧠 How it works

The block works by reading the hostname (SNI) out of the first packet of the TLS handshake. vigil
re-frames that packet: it splits it into smaller TLS records *and* sends its first byte on its own.
The inspecting device never sees the hostname in one piece.

The rest of the connection is **untouched** — once established, data flows as it would otherwise.
No throughput cost.

**Which technique works depends on the ISP**, and vigil learns it per hostname:

| | Türk Telekom (AS9121) | Turkcell Superonline (AS34984) |
|---|---|---|
| Blocking method | RST injection, ~2 ms | Silent drop, 6 s |
| Splitting the first byte (`split:1`) | **20/20** | **0/10** — it even provokes an RST |
| TLS record fragmentation (`tlsrec:64`) | 10/10 | **10/10** |
| Shipped default (`tlsrec:64+split:1`) | 10/10 | 10/10 |

There is no single national preset. **Automatic mode** tries the candidates per host, learns which
one works, and remembers it.

### 📊 Measurements

Measured on the same line at the same moment, direct versus through vigil:

```
Türk Telekom (AS9121)                direct      via vigil
  discord.com                          0/6          6/6
  updates.discord.com                  0/6          6/6
  gateway.discord.gg                   0/6          6/6
  roblox.com  (+6 subdomains)          0/6          6/6
  4chan.org                            0/5          5/5
  example.com            (control)     6/6          6/6

Turkcell Superonline (AS34984)       direct      via vigil
  10 blocked hostnames                 0/6          6/6      (60/60)
```

Throughput is at parity with a direct connection: **80.8 MB/s** through vigil, **78.2 MB/s**
direct.

### 🖱️ The tray menu

| | |
|---|---|
| **Korumayı aç / kapat** | System proxy + `HTTPS_PROXY` |
| **Mod** | automatic *(recommended)* · `tlsrec:64+split:1` · `split:1` · `tlsrec:64` · passthrough |
| **DNS'i de vigil'e ver** | Asks for administrator rights. For programs that ignore the proxy |
| **Windows ile başlat** | Optional |
| **Ayrıntılar…** | Counters, and the strategy learned for each host |

### 🌐 DNS

On some lines the ISP resolves blocked names to the **wrong address** (measured: `discord.com` →
`195.175.254.2`, the block page). vigil uses its own resolver, so anything going through the proxy
is unaffected.

The **"DNS'i de vigil'e ver"** option fixes it for programs that never use the proxy either. It is
the one action that needs administrator rights, because it writes to a Windows network setting. It
restores on exit and always writes a public fallback (`9.9.9.9`) behind itself, so a stopped vigil
still leaves the machine resolving names.

### ❓ FAQ

* **My internet is gone / nothing loads.** Double-click `vigil-repair.exe`. It restores the
  settings.
* **Discord/Roblox still will not open.** Did you restart the application *after* turning
  protection on? Environment variables are read at process start.
* **Discord voice does not work.** Voice runs over UDP and no CONNECT proxy can carry it. Known
  limitation.
* **Does it slow anything down?** No. Only the first packet is changed; the rest flows untouched.
* **Will it affect my bank or e-Devlet?** No. `*.gov.tr` and Turkish banks are on an exclude list
  by default and are never touched.
* **Are the settings restored when I quit?** Yes — on exit, on Ctrl-C, and on Windows shutdown.

### 🔨 Building from source

```bash
git clone https://github.com/resul-e/vigil
cd vigil
cargo test --workspace                 # the tests run on Linux too
cargo build --release --target x86_64-pc-windows-msvc
```

The core logic (`core/`) has **zero dependencies** and is pure: bytes in, bytes out. Everything
that touches the operating system lives in `platform/` and is deliberately thin.

### 🔮 Roadmap

* [ ] **Auto-update** — all files, over the censored line itself
* [ ] **Start engaged at logon** — today "start with Windows" starts the program, not the protection
* [ ] **macOS build** — roughly 90 % of the code is already portable
* [ ] **Transparent builds via CI** — GitHub Actions, signed releases

---

## ⚖️ Sorumluluk reddi / Disclaimer

### 🇹🇷 Türkçe

Bu yazılım **yalnızca eğitim ve araştırma amacıyla** yayınlanmıştır. Ağ protokollerinin, derin paket
incelemesinin (DPI) ve TLS el sıkışmasının nasıl çalıştığını göstermek için yazılmıştır.

**Kullanmayı seçerseniz, sonuçları tamamen sizin sorumluluğunuzdadır.** Bulunduğunuz yerdeki
yasalara, internet servis sağlayıcınızın kullanım koşullarına ve eriştiğiniz hizmetlerin kurallarına
uymak size aittir. Yazar, bu yazılımın kullanımından doğabilecek hiçbir hukuki, mali veya teknik
sonuçtan sorumlu değildir.

Yazılım **hiçbir garanti verilmeksizin, "olduğu gibi"** sunulmaktadır — ayrıntılar için
[LICENSE](LICENSE) dosyasına bakın. Bu bir anonimlik aracı **değildir**: trafiğinizi şifrelemez,
gizlemez ve IP adresinizi saklamaz. Yalnızca TLS el sıkışmasının ilk paketinin nasıl yazıldığını
değiştirir.

### 🇬🇧 English

This software is published **for educational and research purposes only.** It exists to demonstrate
how network protocols, deep packet inspection and the TLS handshake actually work.

**If you choose to use it, whatever happens is your own responsibility.** Complying with the laws
where you are, with your internet service provider's terms, and with the rules of the services you
connect to is up to you. The author accepts no liability for any legal, financial or technical
consequence arising from the use of this software.

It is provided **"as is", with no warranty of any kind** — see [LICENSE](LICENSE). It is **not** an
anonymity tool: it does not encrypt, hide or tunnel your traffic and it does not conceal your IP
address. All it changes is how the first packet of a TLS handshake is written onto the socket.
