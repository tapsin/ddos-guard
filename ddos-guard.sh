#!/bin/bash
# ddos-guard.sh
# Mikrotik "stage" mantığının iptables + ipset karşılığı + genel DDoS/DNS önlemleri.
#
# İlk çalıştırmada KURULUM SİHİRBAZI açılır: beyaz liste, TCP ve UDP portları
# sırayla sorulur, her komutun ne yaptığı açıklanır, ayarlar /etc/ddos-guard.conf'a yazılır.
#
# Komutlar (root gerektirenler sudo ile):
#   sudo ./ddos-guard.sh setup        -> kurulum sihirbazı (beyaz liste + portlar + açıklama)
#   sudo ./ddos-guard.sh ports        -> sadece portları yeniden seç (sıralı ekleme)
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
DNS_PORT=53
TIMEOUT_STAGE=60

# Varsayılanlar (conf dosyası yoksa)
WHITELIST_CSV="127.0.0.1"
WHITELIST_IPS="127.0.0.1"
PORTS_TCP_CSV="22,80,443"
PORTS_UDP_CSV=""
SYN_RATE="50/second"; SYN_BURST=100
DNS_UDP_RATE="30/second"; DNS_UDP_BURST=60
DNS_TCP_CONN=20
ICMP_RATE="5/second"; ICMP_BURST=10
UDP_RATE="100/second"; UDP_BURST=200
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
    WHITELIST_IPS="${WHITELIST_CSV//,/ }"
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
# Portlar
# ---------------------------------------------------------------
# Dinleyen portları protokole göre (tcp/udp) ve süreç adlarıyla listeler.
# $1 = tcp | udp
list_ports() {
    local proto="$1" flag
    if [ "$proto" = "tcp" ]; then flag="-tlnpH"; else flag="-ulnpH"; fi
    ss $flag 2>/dev/null | awk '{
        n = split($4, a, ":"); port = a[n];
        proc = "-";
        if (match($0, /users:\(\("[^"]+"/)) { proc = substr($0, RSTART+9, RLENGTH-10) }
        printf "%s\t%s\n", port, proc
    }' | sort -n -u -k1,1 | awk -F'\t' '{ printf "  %-7s %s\n", $1, $2 }'
}

# Dinleyen tüm portları virgüllü CSV olarak verir (tcp | udp)
all_listening_csv() {
    local flag
    if [ "$1" = "tcp" ]; then flag="-tlnH"; else flag="-ulnH"; fi
    ss $flag 2>/dev/null | awk '{ n = split($4, a, ":"); print a[n] }' \
        | grep -E '^[0-9]+$' | sort -n -u | paste -sd, -
}

# Sıralı port ekleme: her seferinde bir port, sıra korunur.
# $1 = tcp | udp ; sonuç: PORTS_<PROTO>_CSV değişkenine yazılır.
add_ports_sequential() {
    local proto="$1" label input current="" count=0
    label=$(echo "$proto" | tr 'a-z' 'A-Z')
    echo
    echo "=== $label PORTLARI ==="
    echo "Sistemde şu an dinleyen $label portları:"
    list_ports "$proto"
    echo
    echo "Portları sırayla girin, her seferinde bir port. Bitirmek için boş Enter."
    while true; do
        read -r -p "$label port ekle (boş = bitir): " input
        input="$(echo "$input" | tr -d ' ')"
        [ -z "$input" ] && break
        if ! [[ "$input" =~ ^[0-9]{1,5}$ ]] || [ "$input" -lt 1 ] || [ "$input" -gt 65535 ]; then
            echo "  Geçersiz port: '$input' (1-65535 arası olmalı)."
            continue
        fi
        if echo ",$current," | grep -q ",$input,"; then
            echo "  $input zaten seçili."
            continue
        fi
        current="${current:+$current,}$input"
        count=$((count + 1))
        echo "  Seçili $label portları (sırayla): $current"
    done
    eval "PORTS_${label}_CSV=\"\$current\""
}

# Boş bırakılan TCP/UDP listesi için risk açıklaması ve "tümüne uygula" seçeneği.
# $1 = tcp | udp
offer_all_ports() {
    local proto="$1" label all
    label=$(echo "$proto" | tr 'a-z' 'A-Z')
    all=$(all_listening_csv "$proto")
    echo
    echo "$label portu seçmediniz."
    if [ -z "$all" ]; then
        echo "Sistemde dinleyen $label portu bulunamadı; bu protokol için koruma uygulanmayacak."
        eval "PORTS_${label}_CSV=\"\""
        return
    fi
    echo "Sistemde dinleyen $label portları: $all"
    echo
    echo "RİSKLER (tüm $label portlarına uygularsanız):"
    if [ "$proto" = "tcp" ]; then
        echo "  - Dinleyen TÜM TCP portları kademeli engelleme (stage) kurallarına girer."
        echo "  - Mail (25/465/587/993), panel, veritabanı veya sürekli bağlanan uygulamalar"
        echo "    meşru olarak çok bağlantı açabilir; bunlar yanlışlıkla SÜRESİZ banlanabilir."
        echo "  - 53 (DNS) dahilse DNS sorguları da bu kurallara tabi olur."
        echo "  - Beyaz listede olmayan kendi bağlantınız da engellenebilir."
    else
        echo "  - Dinleyen TÜM UDP portlarına kaynak IP başına paket hızı sınırı uygulanır."
        echo "  - DNS (53) ve QUIC/HTTP3 (443/udp) gibi yoğun UDP trafiği sınırlanabilir."
    fi
    echo "  - Bu portlar sistemde bir süreç tarafından dinlenen portlardır; giden (dış) bağlantılar etkilenmez."
    echo
    if ask_yes_no "Tüm dinleyen $label portlarına ($all) uygulansın mı?"; then
        eval "PORTS_${label}_CSV=\"\$all\""
    else
        if [ "$proto" = "tcp" ]; then
            eval "PORTS_TCP_CSV=\"22,80,443\""
            echo "Varsayılan TCP listesi kullanılacak: 22,80,443"
        else
            eval "PORTS_UDP_CSV=\"\""
            echo "UDP için koruma uygulanmayacak."
        fi
    fi
}

# Kullanıcıdan TCP ve UDP portlarını sırayla ister.
ask_ports() {
    echo
    echo "=== KORUNACAK PORTLAR ==="
    echo "TCP portları: yeni bağlantılar kademeli engelleme (stage) + anti-flood'dan geçer,"
    echo "              aşırı bağlantı açan IP'ler SÜRESİZ banlanır."
    echo "UDP portları: kaynak IP başına paket hızı sınırlanır (stage yok)."
    echo "Önce TCP, sonra UDP sorulacak."

    add_ports_sequential tcp
    if [ -z "$PORTS_TCP_CSV" ]; then
        offer_all_ports tcp
    fi

    add_ports_sequential udp
    if [ -z "$PORTS_UDP_CSV" ]; then
        offer_all_ports udp
    fi

    if echo ",$PORTS_TCP_CSV,$PORTS_UDP_CSV," | grep -q ",53,"; then
        echo "UYARI: 53 (DNS) seçili. DNS trafiğini etkileyebilir; DNS için ayrı hız sınırı zaten var."
    fi

    echo
    echo "Seçilen TCP portları : ${PORTS_TCP_CSV:-(yok)}"
    echo "Seçilen UDP portları : ${PORTS_UDP_CSV:-(yok)}"
}

# Port listesini 15'lik parçalara böler (iptables multiport sınırı).
# Her parça ayrı satırda yazılır.
port_chunks() {
    local csv="$1"
    [ -z "$csv" ] && return
    echo "$csv" | tr ',' '\n' | awk 'NF {
        buf = buf (n ? "," : "") $0; n++
        if (n == 15) { print buf; buf = ""; n = 0 }
    } END { if (n) print buf }'
}

# Ayar dosyasını yazar (beyaz liste ve portlar).
write_conf() {
    cat > "$CONF_FILE" << EOF
# ddos-guard.sh ayarları (kurulum tarafından oluşturuldu)
# Beyaz liste (virgülle ayrılmış): kısıtlanmayacak IP / CIDR'ler
WHITELIST_CSV="$WHITELIST_CSV"
# Korunacak TCP portları (sırayla seçilmiş, virgülle ayrılmış)
PORTS_TCP_CSV="$PORTS_TCP_CSV"
# Korunacak UDP portları (sırayla seçilmiş, virgülle ayrılmış; boş olabilir)
PORTS_UDP_CSV="$PORTS_UDP_CSV"
EOF
    chmod 600 "$CONF_FILE"
}

ports_cmd() {
    need_root ports
    load_conf
    ask_ports
    write_conf
    echo
    echo "Portlar kaydedildi: $CONF_FILE"
    if ask_yes_no "Yeni port listesi şimdi uygulansın mı (apply)?"; then
        apply
    else
        echo "Uygulanmadı. Daha sonra: sudo $0 apply"
    fi
}

# ---------------------------------------------------------------
# Kurulum sihirbazı
# ---------------------------------------------------------------
explain_commands() {
cat << 'EOF'
------------------------------------------------------------
 Bu script ne yapar ve komutlar ne yapar?
------------------------------------------------------------
 setup       Kurulum sihirbazı: beyaz liste, TCP ve UDP portları (sırayla) ve
             ayarların kaydı. Sonunda apply'ı isteğe bağlı çalıştırır.
             Sonuç: /etc/ddos-guard.conf oluşur; sistem henüz değişmez (apply istenirse).

 ports       Sadece portları yeniden seçer (sıralı ekleme). Sonra apply sorulur.
             Sonuç: yeni port listesi kaydedilir.

 apply       Güvenlik duvarına (iptables) koruma kuralları ekler.
             - Seçilen TCP portlarına gelen yeni bağlantılar kademeli engellemeden geçer:
               60 sn geçici liste, tekrarlarsa kademe kademe yükselir; en üstte SÜRESİZ ban.
             - SYN flood, ping flood ve DNS (53) hız sınırı uygular.
             - Seçilen UDP portlarına kaynak IP başına paket hızı sınırı uygular.
             - Beyaz listedeki IP'lere hiçbir kısıtlama uygulanmaz.
             Sonuç: normal kullanıcılar etkilenmez; saldırgan IP'ler düşürülür.

 remove      apply ile eklenen tüm kuralları ve listeleri siler.
             Sonuç: koruma kalkar, sunucu eski haline döner.

 status      Engellenen IP'leri ve düşürülen paket sayısını gösterir. Değişiklik yapmaz.

 unban IP    Süresiz engellenmiş bir IP'yi listeden çıkarır.
             Sonuç: o IP tekrar bağlanabilir.

 dns-check   named (DNS) özyineleme ayarını gösterir. Değişiklik yapmaz.

 harden-dns  named'da özyineleme yalnızca localhost'a açılır.
             Sunucu alan adlarını dış dünyaya çözmeye DEVAM EDER (yetkili yanıtlar
             etkilenmez). Önce yedek alır, doğrular, hata olursa geri döner.
             Sonuç: DNS amplifikasyon (yansıtma) saldırılarına karşı riski azaltır.

 Uyarı: apply ve harden-dns sunucuda gerçek değişiklik yapar. Beyaz listenize
        kendi IP'nizi eklemeyi unutmayın; aksi halde kendinizi kilitleyebilirsiniz.
        Port boş bırakılırsa tüm açık portlara uygulanabilir; bu riskler setup'ta gösterilir.
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

    local input ip ok parts=() list=() uniq
    while true; do
        read -r -p "Beyaz liste IP'leri: " input
        list=()
        ok=1
        [ -z "$(echo "$input" | tr -d ' ')" ] && break
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

    list+=("127.0.0.1")
    uniq=$(printf '%s\n' "${list[@]}" | awk '!seen[$0]++' | paste -sd, -)
    WHITELIST_CSV="$uniq"

    echo
    echo "Kaydedilecek beyaz liste: $uniq"

    ask_ports
    write_conf
    echo
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
    local chunk
    iptables -N "$FLOOD_CHAIN" 2>/dev/null || iptables -F "$FLOOD_CHAIN"
    iptables -A "$FLOOD_CHAIN" -m set --match-set whitelist src -j RETURN
    iptables -A "$FLOOD_CHAIN" -m conntrack --ctstate INVALID -j DROP
    iptables -A "$FLOOD_CHAIN" -f -j DROP
    # SYN flood: seçili TCP portları (15'lik parçalar halinde)
    while read -r chunk; do
        [ -z "$chunk" ] && continue
        iptables -A "$FLOOD_CHAIN" -p tcp -m multiport --dports "$chunk" --syn \
            -m hashlimit --hashlimit-name syn_flood --hashlimit-mode srcip \
            --hashlimit-above "$SYN_RATE" --hashlimit-burst "$SYN_BURST" -j DROP
    done < <(port_chunks "$PORTS_TCP_CSV")
    iptables -A "$FLOOD_CHAIN" -p icmp --icmp-type echo-request \
        -m limit --limit "$ICMP_RATE" --limit-burst "$ICMP_BURST" -j RETURN
    iptables -A "$FLOOD_CHAIN" -p icmp --icmp-type echo-request -j DROP
    iptables -A "$FLOOD_CHAIN" -p udp --dport "$DNS_PORT" \
        -m hashlimit --hashlimit-name dns_udp --hashlimit-mode srcip \
        --hashlimit-above "$DNS_UDP_RATE" --hashlimit-burst "$DNS_UDP_BURST" -j DROP
    iptables -A "$FLOOD_CHAIN" -p tcp --dport "$DNS_PORT" --syn \
        -m connlimit --connlimit-above "$DNS_TCP_CONN" --connlimit-mask 32 -j DROP
    # Seçili UDP portları: kaynak IP başına paket hızı sınırı (15'lik parçalar)
    while read -r chunk; do
        [ -z "$chunk" ] && continue
        iptables -A "$FLOOD_CHAIN" -p udp -m multiport --dports "$chunk" \
            -m hashlimit --hashlimit-name udp_guard --hashlimit-mode srcip \
            --hashlimit-above "$UDP_RATE" --hashlimit-burst "$UDP_BURST" -j DROP
    done < <(port_chunks "$PORTS_UDP_CSV")
    iptables -A "$FLOOD_CHAIN" -j RETURN
}

# DDOS_GUARD'a giden atlama kurallarını (her TCP parçası için) ekler/siler
link_chains() {
    local chunk
    iptables -D INPUT -j "$FLOOD_CHAIN" 2>/dev/null
    while read -r chunk; do
        [ -z "$chunk" ] && continue
        iptables -D INPUT -p tcp -m multiport --dports "$chunk" -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null
    done < <(port_chunks "$PORTS_TCP_CSV")
    while read -r chunk; do
        [ -z "$chunk" ] && continue
        iptables -I INPUT 1 -p tcp -m multiport --dports "$chunk" -m conntrack --ctstate NEW -j "$CHAIN"
    done < <(port_chunks "$PORTS_TCP_CSV")
    iptables -I INPUT 1 -j "$FLOOD_CHAIN"
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

apply() {
    need_root apply
    load_conf
    warn_fw
    create_sets
    apply_stage
    apply_flood
    link_chains
    echo "Koruma uygulandı."
    echo "  Stage kademeleri : TCP ${PORTS_TCP_CSV:-(yok)} (60 sn, sonra süresiz ban)"
    echo "  UDP korumalı     : ${PORTS_UDP_CSV:-(yok)}"
    echo "  Anti-flood       : SYN $SYN_RATE, ICMP $ICMP_RATE, DNS UDP $DNS_UDP_RATE, DNS TCP $DNS_TCP_CONN bağlantı"
    echo "  Beyaz liste      : $WHITELIST_CSV"
}

remove() {
    need_root remove
    load_conf
    local chunk
    iptables -D INPUT -j "$FLOOD_CHAIN" 2>/dev/null
    while read -r chunk; do
        [ -z "$chunk" ] && continue
        iptables -D INPUT -p tcp -m multiport --dports "$chunk" -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null
    done < <(port_chunks "$PORTS_TCP_CSV")
    iptables -F "$FLOOD_CHAIN" 2>/dev/null; iptables -X "$FLOOD_CHAIN" 2>/dev/null
    iptables -F "$CHAIN" 2>/dev/null;       iptables -X "$CHAIN" 2>/dev/null
    for s in stage1 stage2 stage3 stage4 blocked whitelist; do
        ipset destroy "$s" 2>/dev/null
    done
    echo "Koruma kaldırıldı."
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
    ports)      ports_cmd ;;
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
        echo "Kullanım: $0 {setup|ports|apply|remove|status|unban IP|dns-check|harden-dns|help}"
        exit 1
        ;;
esac
