#!/bin/bash
# ddos-guard.sh
# Mikrotik "stage" mantığının iptables + ipset karşılığı + genel DDoS/DNS önlemleri.
#
# İlk çalıştırmada KURULUM SİHİRBAZI açılır: beyaz listeyi ister, her komutun ne
# yaptığını ve sonucunu açıklar, ayarları /etc/ddos-guard.conf dosyasına kaydeder.
#
# Komutlar (root):
#   sudo ./ddos-guard.sh setup        -> kurulum sihirbazı (ayarlar + açıklama)
#   sudo ./ddos-guard.sh apply        -> koruma kurallarını uygular
#   sudo ./ddos-guard.sh remove       -> uygulanan kuralları kaldırır
#   sudo ./ddos-guard.sh status       -> listeler, sayaçlar, DNS durumu
#   sudo ./ddos-guard.sh unban IP     -> IP'yi süresiz ban listesinden çıkarır
#   sudo ./ddos-guard.sh dns-check    -> named özyineleme ayarını gösterir (değiştirmez)
#   sudo ./ddos-guard.sh harden-dns   -> named özyinelemesini yalnızca localhost yapar
#   ./ddos-guard.sh help              -> her komutun ne yaptığını ve sonucunu açıklar

set -u

CONF_FILE="/etc/ddos-guard.conf"
CHAIN="DDOS_GUARD"
FLOOD_CHAIN="ANTI_FLOOD"
PORTS="22,80,443"
DNS_PORT=53
TIMEOUT_STAGE=60

# Varsayılanlar (conf dosyası yoksa)
WHITELIST_IPS="127.0.0.1"
SYN_RATE="50/second"; SYN_BURST=100
DNS_UDP_RATE="30/second"; DNS_UDP_BURST=60
DNS_TCP_CONN=20
ICMP_RATE="5/second"; ICMP_BURST=10
NAMED_CONF_CANDIDATES="/etc/named.conf /etc/bind/named.conf.options"

# ---------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------
need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Bu komut root olarak çalışmalı: sudo $0 $1" >&2
        exit 1
    fi
}

load_conf() {
    if [ -f "$CONF_FILE" ]; then
        # shellcheck disable=SC1090
        . "$CONF_FILE"
    fi
}

ask_yes_no() {
    # $1 = soru; varsayılan HAYIR
    local ans
    read -r -p "$1 [e/H]: " ans
    case "$ans" in
        e|E|y|Y|evet|EVET) return 0 ;;
        *) return 1 ;;
    esac
}

# Tek bir IPv4 veya CIDR (ör. 1.2.3.4 veya 1.2.3.0/24) kontrolü
valid_ip_or_cidr() {
    local ip="$1" o1 o2 o3 o4 mask
    if [[ "$ip" == */* ]]; then
        mask="${ip#*/}"; ip="${ip%/*}"
        [[ "$mask" =~ ^[0-9]+$ ]] && [ "$mask" -ge 0 ] && [ "$mask" -le 32 ] || return 1
    fi
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    o1=${BASH_REMATCH[1]}; o2=${BASH_REMATCH[2]}; o3=${BASH_REMATCH[3]}; o4=${BASH_REMATCH[4]}
    for o in "$o1" "$o2" "$o3" "$o4"; do
        [ "$o" -le 255 ] || return 1
    done
    return 0
}

# ---------------------------------------------------------------
# Kurulum sihirbazı
# ---------------------------------------------------------------
explain_commands() {
cat << 'EOF'
------------------------------------------------------------
 Bu script ne yapar ve komutlar ne yapar?
------------------------------------------------------------
 apply       Güvenlik duvarına (iptables) koruma kuralları ekler.
             - 22/80/443 için: bir IP kısa sürede çok yeni bağlantı açarsa
               önce geçici listeye (60 sn), tekrarlarsa kademe kademe yükselir.
               En üst kademede IP SÜRESİZ engellenir.
             - SYN flood, ping (ICMP) flood ve DNS (53) hız sınırı uygular.
             - Beyaz listedeki IP'lere hiçbir kısıtlama uygulanmaz.
             Sonuç: normal kullanıcılar etkilenmez; saldırgan IP'ler düşürülür.

 remove      apply ile eklenen tüm kuralları ve listeleri siler.
             Sonuç: koruma kalkar, sunucu eski haline döner.

 status      Hangi IP'lerin engellendiğini ve kaç paket düşürüldüğünü gösterir.
             Sonuç: sadece görüntüler, değişiklik yapmaz.

 unban IP    Süresiz engellenmiş bir IP'yi listeden çıkarır.
             Sonuç: o IP tekrar bağlanabilir.

 dns-check   named (DNS) ayarında özyineleme (recursion) kimlere açık, gösterir.
             Sonuç: sadece görüntüler, değişiklik yapmaz.

 harden-dns  named'da özyineleme yalnızca localhost'a açılır.
             Sunucu alan adlarını dış dünyaya çözmeye DEVAM EDER (yetkili yanıtlar
             etkilenmez). Sadece dışarıdaki kişilerin sunucuyu DNS yükseltmesi için
             kullanmasını engeller. Önce yedek alır, doğrular, hata olursa geri döner.
             Sonuç: DNS amplifikasyon (yansıtma) saldırılarına karşı riski azaltır.

 Uyarı: apply ve harden-dns sunucuda gerçek değişiklik yapar. Beyaz listenize
        kendi IP'nizi eklemeyi unutmayın; aksi halde kendinizi kilitleyebilirsiniz.
------------------------------------------------------------
EOF
}

setup() {
    need_root setup
    echo
    echo "=== ddos-guard.sh KURULUM SİHİRBAZI ==="
    echo
    explain_commands
    echo
    echo "Beyaz liste: bu IP'lere hiçbir kısıtlama uygulanmaz (kendi IP'niz, ofis, izleme sistemleri)."
    echo "Birden fazla IP'yi virgülle yazın. Örnek: 212.175.193.175,10.0.0.5,192.168.1.0/24"
    echo "Boş bırakırsanız sadece 127.0.0.1 eklenir."
    echo

    local input ip list=()
    while true; do
        read -r -p "Beyaz liste IP'leri: " input
        list=()
        local ok=1
        if [ -z "$(echo "$input" | tr -d ' ')" ]; then
            break
        fi
        IFS=',' read -ra parts <<< "$input"
        for p in "${parts[@]}"; do
            ip="$(echo "$p" | tr -d ' ')"
            [ -z "$ip" ] && continue
            if valid_ip_or_cidr "$ip"; then
                list+=("$ip")
            else
                echo "  Geçersiz adres: '$ip' (IPv4 veya IPv4/24 bekleniyor). Tekrar girin."
                ok=0
                break
            fi
        done
        [ $ok -eq 1 ] && break
    done

    # 127.0.0.1 her zaman ekli olsun
    list+=("127.0.0.1")
    # tekrarları kaldır
    local uniq
    uniq=$(printf '%s\n' "${list[@]}" | awk '!seen[$0]++' | paste -sd, -)
    WHITELIST_IPS=$(echo "$uniq" | tr ',' ' ')

    echo
    echo "Kaydedilecek beyaz liste: $uniq"
    cat > "$CONF_FILE" << EOF
# ddos-guard.sh ayarları (setup tarafından oluşturuldu)
# Beyaz liste (virgülle ayrılmış): kısıtlanmayacak IP / CIDR'ler
WHITELIST_CSV="$uniq"
WHITELIST_IPS="\${WHITELIST_CSV//,/ }"
EOF
    chmod 600 "$CONF_FILE"
    echo "Ayarlar kaydedildi: $CONF_FILE (sadece root okuyabilir)"
    echo

    if ask_yes_no "Koruma şimdi uygulansın mı (apply)?"; then
        apply
    else
        echo "Uygulanmadı. Daha sonra: sudo $0 apply"
    fi
}

# ---------------------------------------------------------------
# Koruma kuralları
# ---------------------------------------------------------------
create_sets() {
    ipset create whitelist hash:net -exist
    for s in stage1 stage2 stage3 stage4; do
        ipset create "$s" hash:ip timeout "$TIMEOUT_STAGE" -exist
    done
    ipset create blocked hash:ip timeout 0 -exist
    ipset flush whitelist
    for ip in $WHITELIST_IPS; do
        ipset add whitelist "$ip" -exist
    done
}

apply_stage() {
    iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
    iptables -A "$CHAIN" -m set --match-set whitelist src -j RETURN
    iptables -A "$CHAIN" -m set --match-set blocked src -j DROP
    iptables -A "$CHAIN" -m set --match-set stage4 src -j SET --add-set blocked src --exist
    iptables -A "$CHAIN" -m set --match-set stage3 src -j SET --add-set stage4 src --exist
    iptables -A "$CHAIN" -m set --match-set stage2 src -j SET --add-set stage3 src --exist
    iptables -A "$CHAIN" -m set --match-set stage1 src -j SET --add-set stage2 src --exist
    iptables -A "$CHAIN" -j SET --add-set stage1 src --exist
}

apply_flood() {
    iptables -N "$FLOOD_CHAIN" 2>/dev/null || iptables -F "$FLOOD_CHAIN"
    iptables -A "$FLOOD_CHAIN" -m set --match-set whitelist src -j RETURN
    iptables -A "$FLOOD_CHAIN" -m conntrack --ctstate INVALID -j DROP
    iptables -A "$FLOOD_CHAIN" -f -j DROP
    iptables -A "$FLOOD_CHAIN" -p tcp -m multiport --dports "$PORTS" --syn \
        -m hashlimit --hashlimit-name syn_flood --hashlimit-mode srcip \
        --hashlimit-above "$SYN_RATE" --hashlimit-burst "$SYN_BURST" -j DROP
    iptables -A "$FLOOD_CHAIN" -p icmp --icmp-type echo-request \
        -m limit --limit "$ICMP_RATE" --limit-burst "$ICMP_BURST" -j RETURN
    iptables -A "$FLOOD_CHAIN" -p icmp --icmp-type echo-request -j DROP
    iptables -A "$FLOOD_CHAIN" -p udp --dport "$DNS_PORT" \
        -m hashlimit --hashlimit-name dns_udp --hashlimit-mode srcip \
        --hashlimit-above "$DNS_UDP_RATE" --hashlimit-burst "$DNS_UDP_BURST" -j DROP
    iptables -A "$FLOOD_CHAIN" -p tcp --dport "$DNS_PORT" --syn \
        -m connlimit --connlimit-above "$DNS_TCP_CONN" --connlimit-mask 32 -j DROP
    iptables -A "$FLOOD_CHAIN" -j RETURN
}

link_chains() {
    iptables -D INPUT -j "$FLOOD_CHAIN" 2>/dev/null
    iptables -D INPUT -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null
    iptables -I INPUT 1 -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j "$CHAIN"
    iptables -I INPUT 1 -j "$FLOOD_CHAIN"
}

apply() {
    need_root apply
    load_conf
    warn_fw
    create_sets
    apply_stage
    apply_flood
    link_chains
    echo "Koruma uygulandı."
    echo "  Stage kademeleri : 22/80/443 (60 sn, sonra süresiz ban)"
    echo "  Anti-flood       : SYN $SYN_RATE, ICMP $ICMP_RATE, DNS UDP $DNS_UDP_RATE, DNS TCP $DNS_TCP_CONN bağlantı"
    echo "  Beyaz liste      : $WHITELIST_IPS"
}

remove() {
    need_root remove
    iptables -D INPUT -j "$FLOOD_CHAIN" 2>/dev/null
    iptables -D INPUT -p tcp -m multiport --dports "$PORTS" -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null
    iptables -F "$FLOOD_CHAIN" 2>/dev/null; iptables -X "$FLOOD_CHAIN" 2>/dev/null
    iptables -F "$CHAIN" 2>/dev/null;       iptables -X "$CHAIN" 2>/dev/null
    for s in stage1 stage2 stage3 stage4 blocked whitelist; do
        ipset destroy "$s" 2>/dev/null
    done
    echo "Koruma kaldırıldı."
}

warn_fw() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "UYARI: ufw aktif. Kurallar INPUT zincirine eklenir; ufw reload sonrası kontrol edin."
    elif [ -d /usr/local/csf ]; then
        echo "UYARI: CSF kurulu. 'csf -r' iptables kurallarını silebilir."
    elif [ -d /etc/apf ]; then
        echo "UYARI: APF kurulu. 'apf -r' iptables kurallarını silebilir."
    fi
}

# ---------------------------------------------------------------
# DNS
# ---------------------------------------------------------------
find_named_conf() {
    for f in $NAMED_CONF_CANDIDATES; do
        [ -f "$f" ] && grep -q "allow-recursion" "$f" && { echo "$f"; return; }
    done
    echo ""
}

dns_check() {
    local CONF
    CONF=$(find_named_conf)
    if [ -z "$CONF" ]; then
        echo "named yapılandırmasında allow-recursion bulunamadı."
        return
    fi
    echo "named dosyası: $CONF"
    grep -n -A2 "allow-recursion" "$CONF"
    if grep -A2 "allow-recursion" "$CONF" | grep -qE "localnets|any"; then
        echo "UYARI: Özyineleme yerel ağlara/herkese açık. 'harden-dns' önerilir."
    else
        echo "Özyineleme yalnızca localhost (veya kapalı) görünüyor."
    fi
}

harden_dns() {
    need_root harden-dns
    local CONF BAK
    CONF=$(find_named_conf)
    if [ -z "$CONF" ]; then
        echo "Değiştirilecek named dosyası bulunamadı." >&2
        exit 1
    fi
    if ! command -v named-checkconf >/dev/null 2>&1; then
        echo "named-checkconf yok; güvenlik için işlem iptal edildi." >&2
        exit 1
    fi
    echo "Bu işlem $CONF dosyasındaki allow-recursion'ı localhost yapar."
    echo "Yetkili DNS yanıtları etkilenmez; alan adları çözülmeye devam eder."
    ask_yes_no "Devam edilsin mi?" || { echo "İptal edildi."; exit 0; }

    BAK="${CONF}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -p "$CONF" "$BAK" || exit 1
    echo "Yedek: $BAK"

    python3 - "$CONF" << 'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
new, n = re.subn(r"allow-recursion\s*\{[^}]*\}\s*;", "allow-recursion { localhost; };", s)
if n == 0:
    sys.exit(1)
open(p, "w", encoding="utf-8").write(new)
print("allow-recursion güncellendi:", n, "yer")
PY
    if [ $? -ne 0 ]; then
        cp -p "$BAK" "$CONF"; echo "Hata: geri alındı." >&2; exit 1
    fi

    if named-checkconf >/dev/null 2>&1; then
        systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null
        echo "named doğrulandı ve yeniden yüklendi."
        echo "Kontrol: dig @127.0.0.1 example.com (localhost'tan çalışmalı)."
    else
        cp -p "$BAK" "$CONF"
        echo "named-checkconf hatası: yedek geri yüklendi, named yeniden yüklenmedi." >&2
        exit 1
    fi
}

# ---------------------------------------------------------------
# Durum ve yardım
# ---------------------------------------------------------------
status() {
    need_root status
    load_conf
    echo "== Listeler =="
    for s in whitelist stage1 stage2 stage3 stage4 blocked; do
        printf '%-10s %s giriş\n' "$s" "$(ipset list "$s" 2>/dev/null | grep -c '^[0-9]')"
    done
    echo "== blocked (ilk 20) =="
    ipset list blocked 2>/dev/null | grep '^[0-9]' | head -20
    echo "== $CHAIN sayaçları =="
    iptables -L "$CHAIN" -v -n 2>/dev/null
    echo "== $FLOOD_CHAIN sayaçları =="
    iptables -L "$FLOOD_CHAIN" -v -n 2>/dev/null
    echo "== DNS =="
    dns_check
}

unban() {
    need_root unban
    if [ -z "${1:-}" ]; then
        echo "Kullanım: $0 unban IP" >&2
        exit 1
    fi
    ipset del blocked "$1" && echo "$1 süresiz ban listesinden çıkarıldı."
}

help() {
    explain_commands
}

# ---------------------------------------------------------------
# Giriş noktası
# ---------------------------------------------------------------
case "${1:-}" in
    setup)      setup ;;
    apply)      apply ;;
    remove)     remove ;;
    status)     status ;;
    unban)      unban "${2:-}" ;;
    dns-check)  need_root dns-check; dns_check ;;
    harden-dns) harden_dns ;;
    help|-h|--help) help ;;
    "")
        if [ ! -f "$CONF_FILE" ]; then
            echo "İlk çalıştırma: ayar dosyası bulunamadı, kurulum sihirbazı açılıyor."
            setup
        else
            help
        fi
        ;;
    *)
        echo "Kullanım: $0 {setup|apply|remove|status|unban IP|dns-check|harden-dns|help}"
        exit 1
        ;;
esac
