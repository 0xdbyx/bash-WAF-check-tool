#!/usr/bin/env bash

# ================================================================
# WAF Checker (multi-pass, multi-hop)
# wafchecktool.sh
#
# Detects potential Web Application Firewall (WAF) behavior.
# Checks both HTTP and HTTPS using curl.
# Supports custom User-Agent (mobile or desktop)
# Optional SSL ignore (-k)
# Logs Unknown/None cases for verification
#
# Usage:
#   ./wafchecktool.sh -i input.csv -o output.csv [-u "User-Agent"] [-k] [-s waf_signatures.txt]
#
# ================================================================

set -o errexit
set -o nounset
set -o pipefail

# Defaults
input_file="input.csv"
output_file="output.csv"
ignore_ssl=false
sigfile="waf_signatures.txt"

# UA presets
ua_mobile="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
ua_desktop="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Defaults (can be overridden by -u flag)
user_agent_benign="$ua_mobile"
user_agent_malicious="Mozilla/5.0 <script>"

# Base debug folder
debug_base_dir="./waf_debug_logs"
mkdir -p "$debug_base_dir"

usage() {
cat <<EOF
Usage: $0 [-i input.csv] [-o output.csv] [-k] [-s signatures.txt] [-u desktop|mobile] [-h]
  -i FILE   Input CSV (first column should be host/URL). Default: input.csv
  -o FILE   Output CSV. Default: output.csv
  -k        Ignore SSL certificate errors (curl -k)
  -s FILE   Load additional signatures from FILE (pattern|Vendor)
  -u MODE   User-Agent set: "desktop" or "mobile" (default: mobile)
  -h        Show help
EOF
exit 1
}

while getopts "i:o:ks:hu:" opt; do
    case "$opt" in
        i) input_file="$OPTARG" ;;
        o) output_file="$OPTARG" ;;
        k) ignore_ssl=true ;;
        s) sigfile="$OPTARG" ;;
        u) 
            case "$OPTARG" in
                desktop) user_agent_benign="$ua_desktop" ;;
                mobile)  user_agent_benign="$ua_mobile" ;;
                *) echo "[-] Invalid UA mode: $OPTARG (use desktop|mobile)" >&2; exit 1 ;;
            esac
            ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ ! -f "$input_file" ]; then
    echo "[-] Input file not found: $input_file" >&2
    exit 1
fi

# Built-in signatures (pattern|Vendor)
builtin_sigs=(
"cloudflare|Cloudflare"
"cf-ray|Cloudflare"
"__cfduid|Cloudflare"
"cf_clearance|Cloudflare"
"incapsula|Imperva"
"visid_incap|Imperva"
"incap_ses|Imperva"
"akamai|Akamai"
"akamaiedge|Akamai"
"cloudfront|Amazon CloudFront"
"x-amz-cf-id|Amazon CloudFront"
)

declare -a sig_patterns sig_names
load_signatures() {
    sig_patterns=()
    sig_names=()
    for entry in "${builtin_sigs[@]}"; do
        sig_patterns+=( "${entry%%|*}" )
        sig_names+=( "${entry#*|}" )
    done

    if [ -f "$sigfile" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            if [[ "$line" == *"|"* ]]; then
                sig_patterns+=( "${line%%|*}" )
                sig_names+=( "${line#*|}" )
            fi
        done < "$sigfile"
    fi
}

detect_wafs_multi() {
    local file="$1"
    local -a found=()
    for i in "${!sig_patterns[@]}"; do
        pattern="${sig_patterns[i]}"
        vendor="${sig_names[i]}"
        if grep -qi -- "$pattern" "$file" 2>/dev/null; then
            skip=false
            for x in "${found[@]}"; do
                [[ "$x" == "$vendor" ]] && skip=true && break
            done
            $skip || found+=("$vendor")
        fi
    done
    if [ ${#found[@]} -eq 0 ]; then
        echo "Unknown/None"
    else
        IFS=';' ; echo "${found[*]}"
    fi
}

fingerprint_files() {
    local hdr_file="$1"
    local body_file="${2:-}"
    local debug_dir="$3"  # folder to save Unknown/None logs
    local tmp_merged
    tmp_merged=$(mktemp /tmp/waf_mrg.XXXXXX) || return 0
    cat "$hdr_file" > "$tmp_merged" 2>/dev/null || true
    if [ -n "$body_file" ] && [ -f "$body_file" ]; then
        head -c 65536 "$body_file" >> "$tmp_merged" 2>/dev/null || true
    fi

    local res
    res=$(detect_wafs_multi "$tmp_merged")

    # Save only merged log if Unknown/None
    if [[ "$res" == "Unknown/None" && -n "$debug_dir" ]]; then
        timestamp=$(date +%s)
        mkdir -p "$debug_dir"
        cp "$tmp_merged" "$debug_dir/merged_$timestamp.log"
        echo "[DEBUG] Unknown WAF detected. Saved merged log in $debug_dir" >&2
    fi

    rm -f "$tmp_merged"
    printf "%s" "$res"
}

split_headers_into_hops() {
    local hdrfile="$1"
    local outprefix="${hdrfile}_hop"
    local -a outfiles=()
    awk -v outp="$outprefix" '
    /^HTTP\// { if (f) close(f); f = sprintf("%s%02d", outp, ++n); }
    { if (!f) { f = sprintf("%s%02d", outp, ++n); } print > f }
    END { if (f) close(f) }' "$hdrfile"
    for f in "${outprefix}"*; do
        [ -f "$f" ] || continue
        outfiles+=( "$f" )
    done
    printf "%s" "${outfiles[*]}"
}

curl_pass() {
    local url="$1"
    local mode="$2"
    local ua="$3"
    local tmp_hdr tmp_body tmp_meta
    tmp_hdr=$(mktemp /tmp/waf_hdr.XXXXXX) || return 1
    tmp_body=$(mktemp /tmp/waf_body.XXXXXX) || { rm -f "$tmp_hdr"; return 1; }
    tmp_meta=$(mktemp /tmp/waf_meta.XXXXXX) || { rm -f "$tmp_hdr" "$tmp_body"; return 1; }

    local curl_args=( -s -S -L -D "$tmp_hdr" -A "$ua" )
    $ignore_ssl && curl_args+=( -k )

    if [ "$mode" = "HEAD" ]; then
        if ! curl "${curl_args[@]}" -I "$url" -o /dev/null -w "%{http_code},%{url_effective}" >"$tmp_meta" 2>/dev/null; then
            echo "000,," > "$tmp_meta"
        fi
        : > "$tmp_body"
    else
        if ! curl "${curl_args[@]}" -o "$tmp_body" -w "%{http_code},%{url_effective}" "$url" >"$tmp_meta" 2>/dev/null; then
            echo "000,," > "$tmp_meta"
        fi
    fi

    printf "%s|%s|%s" "$tmp_meta" "$tmp_hdr" "$tmp_body"
}

merge_vendors() {
    local combined=("$@")
    local -A uniq_map=()
    for v in "${combined[@]}"; do
        IFS=';' read -r -a parts <<< "$v"
        for p in "${parts[@]}"; do
            [[ -n "$p" ]] && uniq_map["$p"]=1
        done
    done
    if [ ${#uniq_map[@]} -eq 0 ]; then
        echo "Unknown/None"
    else
        local out
        out=$(printf "%s;" "${!uniq_map[@]}")
        echo "${out%;}"
    fi
}

# Load signatures
load_signatures

# CSV header
printf 'input,http_code,http_wafs,http_final_url,https_code,https_wafs,https_final_url\n' > "$output_file"

first_line=$(head -n1 "$input_file" | tr '[:upper:]' '[:lower:]' || true)
skip_header=false
[[ "$first_line" == *"input"* || "$first_line" == *"url"* || "$first_line" == *"host"* ]] && skip_header=true

{
    if $skip_header; then tail -n +2 "$input_file"; else cat "$input_file"; fi
} | while IFS=, read -r col0 _rest || [ -n "$col0" ]; do
    entry=$(echo "$col0" | sed -E 's/^[[:space:]"'"'"']+|[[:space:]"'"'"']+$//g')
    [ -z "$entry" ] && continue
    entry="${entry%/}"
    stripped=$(echo "$entry" | sed -E 's~^https?://~~I')

    http_url="http://$stripped"
    https_url="https://$stripped"

    target_debug_dir="$debug_base_dir/$stripped"

    run_checks_for() {
        local url="$1"
        local debug_dir="$2"

        pass1=$(curl_pass "$url" "GET" "$user_agent_benign") || true
        meta1=${pass1%%|*}; rest1=${pass1#*|}; hdr1=${rest1%%|*}; body1=${rest1#*|}
        pass2=$(curl_pass "$url" "GET" "$user_agent_malicious") || true
        meta2=${pass2%%|*}; rest2=${pass2#*|}; hdr2=${rest2%%|*}; body2=${rest2#*|}
        pass3=$(curl_pass "$url" "HEAD" "$user_agent_malicious") || true
        meta3=${pass3%%|*}; rest3=${pass3#*|}; hdr3=${rest3%%|*}; body3=${rest3#*|}

        read -r code2 final2 < <(awk -F, '{print $1" "$2}' "$meta2" 2>/dev/null || echo "000 ")
        read -r code1 final1 < <(awk -F, '{print $1" "$2}' "$meta1" 2>/dev/null || echo "000 ")
        read -r code3 final3 < <(awk -F, '{print $1" "$2}' "$meta3" 2>/dev/null || echo "000 ")

        code="000"; final_url=""
        if [[ "$code2" != "000" && -n "$final2" ]]; then code="$code2"; final_url="$final2"
        elif [[ "$code1" != "000" && -n "$final1" ]]; then code="$code1"; final_url="$final1"
        elif [[ "$code3" != "000" && -n "$final3" ]]; then code="$code3"; final_url="$final3"
        fi

        vendors_found=()

        for hdr in "$hdr1" "$hdr2" "$hdr3"; do
            if [ -f "$hdr" ] && [ -s "$hdr" ]; then
                hop_files=$(split_headers_into_hops "$hdr")
                for hopf in $hop_files; do
                    v=$(fingerprint_files "$hopf" "$body1" "$debug_dir")
                    vendors_found+=( "$v" )
                done
            fi
        done

        # fingerprint final bodies
        for pair in "$hdr1:$body1" "$hdr2:$body2"; do
            hdrf="${pair%%:*}"; bodyf="${pair#*:}"
            v=$(fingerprint_files "$hdrf" "$bodyf" "$debug_dir")
            vendors_found+=( "$v" )
        done

        merged=$(merge_vendors "${vendors_found[@]}")

        # Cleanup temp files
        rm -f "$meta1" "$hdr1" "$body1" "$meta2" "$hdr2" "$body2" "$meta3" "$hdr3" "$body3" 2>/dev/null || true

        printf "%s|%s|%s" "$code" "$merged" "$final_url"
    }

    http_out=$(run_checks_for "$http_url" "$target_debug_dir")
    https_out=$(run_checks_for "$https_url" "$target_debug_dir")

    http_code="${http_out%%|*}"; rest_http="${http_out#*|}"; http_wafs="${rest_http%%|*}"; http_final="${rest_http#*|}"
    https_code="${https_out%%|*}"; rest_https="${https_out#*|}"; https_wafs="${rest_https%%|*}"; https_final="${rest_https#*|}"

    http_final_esc=$(printf '%s' "$http_final" | sed 's/"/""/g')
    https_final_esc=$(printf '%s' "$https_final" | sed 's/"/""/g')

    printf '"%s",%s,"%s","%s",%s,"%s","%s"\n' "$stripped" "$http_code" "$http_wafs" "$http_final_esc" "$https_code" "$https_wafs" "$https_final_esc" >> "$output_file"
    printf '[*] Checked %s\n' "$entry" >&2
done

echo "[+] Done. Results: $output_file" >&2
echo "[+] Any Unknown/None cases logged under $debug_base_dir/<target>/" >&2
