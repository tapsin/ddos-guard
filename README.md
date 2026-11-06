# ddos-guard.sh

Linux sunucular için **iptables + ipset** tabanlı, Mikrotik'teki "stage" (kademeli engelleme) mantığını taklit eden DDoS koruma scripti.

## Ne yapar

- **Kademeli engelleme (22, 80, 443):** Bir IP kısa sürede çok yeni bağlantı açarsa önce geçici listeye alınır (60 sn). Tekrarlarsa kademe kademe yükselir; en üst kademede **süresiz** engellenir.
- **Anti-flood:** Geçersiz ve parçalı paketleri düşürür, SYN flood ve ICMP (ping) flood'a karşı hız sınırı koyar.
- **DNS (53) hız sınırı:** Kaynak IP başına UDP sorgu ve TCP bağlantı sınırı uygular.
- **DNS özyineleme kapatma (`harden-dns`):** named'da özyinelemeyi yalnızca `localhost`'a açar. Yetkili DNS yanıtları etkilenmez.
- **Beyaz liste:** Virgülle ayrılmış IP/CIDR listesi; bu adreslere hiçbir kısıtlama uygulanmaz.

## Önemli: DNS hakkında

Dış isteklere 53 numaralı portu tamamen kapatmak, sunucu yetkili DNS hizmeti veriyorsa alan adlarını çözülemez hale getirir. Bu yüzden script 53'ü kapatmaz; yalnızca hız sınırı koyar ve özyinelemeyi kısıtlar.

## Kurulum

```bash
sudo ./ddos-guard.sh
```

İlk çalıştırmada kurulum sihirbazı açılır: her komutun ne yaptığını gösterir, beyaz listeyi virgülle ister ve ayarları `/etc/ddos-guard.conf` dosyasına kaydeder.

## Komutlar

| Komut | Ne yapar |
|---|---|
| `sudo ./ddos-guard.sh setup` | Kurulum sihirbazı (ayarlar + açıklama) |
| `sudo ./ddos-guard.sh apply` | Koruma kurallarını uygular |
| `sudo ./ddos-guard.sh remove` | Uygulanan kuralları kaldırır |
| `sudo ./ddos-guard.sh status` | Listeleri, sayaçları ve DNS durumunu gösterir |
| `sudo ./ddos-guard.sh unban IP` | IP'yi süresiz ban listesinden çıkarır |
| `sudo ./ddos-guard.sh dns-check` | named özyineleme ayarını gösterir (değiştirmez) |
| `sudo ./ddos-guard.sh harden-dns` | named özyinelemesini yalnızca localhost yapar (onay ister, yedek alır) |
| `./ddos-guard.sh help` | Her komutun ne yaptığını açıklar |

## Uyarılar

- **Kendinizi kilitlemeyin:** Uygulamadan önce kendi IP'nizi beyaz listeye ekleyin.
- Yanlış engellenen bir IP için: `sudo ./ddos-guard.sh unban IP`.
- NAT arkasındaki (aynı IP'yi paylaşan) kullanıcılar, çok sayıda bağlantı açarlarsa yanlışlıkla engellenebilir. Eşikleri dosyanın başındaki değişkenlerden ayarlayın.
- Kurallar yeniden başlatmada silinir; kalıcı kullanım için bir systemd servisi ya da `@reboot` cron satırı ekleyin.
- **CSF veya APF kullanıyorsanız** `csf -r` / `apf -r` komutları iptables kurallarını silebilir. Script bu durumda uyarı verir.
- `apply` ve `harden-dns` sunucuda gerçek değişiklik yapar. Kullanmadan önce kodu okuyun ve bir test sunucusunda deneyin.
- Sorumluluk kullanıcıya aittir.

## Gereksinimler

- Linux, root erişimi
- `iptables`, `ipset` (ve `hashlimit`, `connlimit` modülleri)
- `python3` (harden-dns için)
- `named-checkconf` (BIND kuruluysa, harden-dns için)

## Lisans

Bu uygulama lisans gerektirmeyen, ücretsiz bir uygulamadır.

---

## Donate

If you find this project useful, consider supporting its development:

| Network | Address |
|---------|---------|
| **USDT (TRC20)** | `TYCK6ZyMS6UDt787foPH2QwFuvkdqMw1Jv` |
| **USDT (BSC20 / BEP20)** | `0x15aac92a1945ddbe5c79304bfa388d6be99b26a3` |

---

<p align="center">Created by <strong>TAPSIN</strong></p>
