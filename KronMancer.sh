#!/bin/bash

# KronMancer v2.0 - Cron Privilege Escalation Scanner
# A red team tool for detecting privilege escalation via cron jobs
# MITRE ATT&CK: T1053.003 - Scheduled Task/Job: Cron

set -euo pipefail

# Global variables
declare -A ANALYZED_FILES
declare -A VULNERABILITIES
CURRENT_USER=$(whoami)
SCRIPT_DIR=$(dirname "$(realpath "$0")")
LOG_FILE="${SCRIPT_DIR}/cron_privesc_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function - only for vulnerabilities
log() {
    local level="$1"
    shift
    local message="$*"
    if [[ "$level" == "CRITICAL" || "$level" == "HIGH" ]]; then
        echo -e "${RED}[$level] $message${NC}"
    fi
}

# Priority levels
CRITICAL="CRITICAL"
HIGH="HIGH"
MEDIUM="MEDIUM"
LOW="LOW"
INFO="INFO"

#=============================================================================
# PHASE 1: CRON JOB COLLECTION
#=============================================================================

collect_all_cron_jobs() {
    
    local temp_file
    temp_file=$(mktemp)
    
    # System-wide crontab
    if [[ -r /etc/crontab ]]; then
        while IFS= read -r line; do
            # Skip comments, empty lines, and environment variables
            if [[ "$line" =~ ^[[:space:]]*# || "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[A-Z] ]]; then
                continue
            fi
            echo "SYSTEM:/etc/crontab:$line" >> "$temp_file"
        done < /etc/crontab
    fi
    
    # /etc/cron.d entries
    if [[ -d /etc/cron.d ]]; then
        find /etc/cron.d -type f -readable 2>/dev/null | while read -r file; do
            while IFS= read -r line; do
                if [[ "$line" =~ ^[[:space:]]*# || "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[A-Z] ]]; then
                    continue
                fi
                echo "CROND:$file:$line" >> "$temp_file"
            done < "$file"
        done
    fi
    
    # Run-parts directories
    for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f -executable 2>/dev/null | while read -r script; do
                echo "RUNPARTS:$dir:$script" >> "$temp_file"
            done
        fi
    done
    
    # User crontabs (focus on root and service accounts)
    if [[ -d /var/spool/cron/crontabs ]]; then
        find /var/spool/cron/crontabs -type f -readable 2>/dev/null | while read -r file; do
            local user
            user=$(basename "$file")
            local is_privileged=false
            # Focus on privileged users
            if [[ "$user" == "root" ]] || id "$user" 2>&1 | grep -qE "(uid=0|sudo|admin|wheel)"; then
                is_privileged=true
            fi
            
            if [[ "$is_privileged" == "true" ]]; then
                while IFS= read -r line; do
                    if [[ "$line" =~ ^[[:space:]]*# || "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[A-Z] ]]; then
                        continue
                    fi
                    echo "USER:$user:$line" >> "$temp_file"
                done < "$file"
            fi
        done
    fi
    
    # Systemd timers (modern cron alternative)
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-timers --all --no-pager 2>&1 | tail -n +2 | head -n -2 | while read -r line; do
            local timer_name
            timer_name=$(echo "$line" | awk '{print $NF}')
            if [[ "$timer_name" =~ \.timer$ ]]; then
                local service_name="${timer_name%.timer}.service"
                local exec_start
                exec_start=$(systemctl show "$service_name" --property=ExecStart --no-pager 2>/dev/null | cut -d= -f2-)
                if [[ -n "$exec_start" ]]; then
                    echo "SYSTEMD:$timer_name:$exec_start" >> "$temp_file"
                fi
            fi
        done
    fi
    
    # Output collected entries
    cat "$temp_file"
    rm -f "$temp_file"
}

#=============================================================================
# PHASE 2: WRITE ACCESS ANALYSIS
#=============================================================================

check_write_access() {
    local target_file="$1"
    
    # Direct file write access
    if [[ -w "$target_file" ]] 2>/dev/null; then
        echo "DIRECT_WRITE:$target_file"
        log "$CRITICAL" "Direct write access to: $target_file"
    fi
    
    # Parent directory analysis (symlink attack potential)
    local current_dir="$target_file"
    local depth=0
    while [[ "$current_dir" != "/" && $depth -lt 10 ]]; do
        current_dir=$(dirname "$current_dir")
        if [[ -w "$current_dir" ]] 2>/dev/null; then
            echo "PARENT_WRITE:$current_dir:$target_file"
            log "$HIGH" "Writable parent directory: $current_dir (target: $target_file)"
        fi
        ((depth++))
    done
    
    # Check for missing files (creation opportunity)
    if [[ ! -f "$target_file" ]]; then
        local parent_dir
        parent_dir=$(dirname "$target_file")
        if [[ -w "$parent_dir" ]] 2>/dev/null; then
            echo "MISSING_FILE:$target_file:$parent_dir"
            log "$HIGH" "Missing file in writable directory: $target_file"
        fi
    fi
}

#=============================================================================
# PATH INJECTION ANALYSIS
#=============================================================================

analyze_path_injection() {
    local target_file="$1"
    local cron_path="${2:-/usr/bin:/bin}"
    
    if [[ ! -r "$target_file" ]]; then
        return
    fi
    
    # Extract potential command executions using safer approach
    local temp_commands
    temp_commands=$(mktemp)
    
    # Direct command calls (not starting with /, ./, or ~/)
    grep -oE '\b[a-zA-Z_][a-zA-Z0-9_-]*\b' "$target_file" 2>/dev/null | \
    grep -vE '^(if|then|else|elif|fi|for|while|do|done|case|esac|function|return|exit|echo|test|true|false|break|continue)$' | \
    sort -u > "$temp_commands" || true
    
    # Command substitutions
    grep -oE '\$\([^)]+\)|`[^`]+`' "$target_file" 2>/dev/null | \
    sed -E 's/\$\(|\`//g; s/\)|\`//g' | \
    awk '{print $1}' | \
    grep -vE '^(/|\./|~/)' | \
    sort -u >> "$temp_commands" || true
    
    # Shebang interpreters
    head -1 "$target_file" 2>/dev/null | \
    grep -oE '#![[:space:]]*[^[:space:]]+' | \
    sed 's/#![[:space:]]*//' | \
    grep -vE '^/' >> "$temp_commands" 2>/dev/null || true
    
    # Check each command
    while read -r cmd; do
        if [[ -z "$cmd" || "$cmd" =~ ^[0-9]+$ || ${#cmd} -lt 2 ]]; then
            continue
        fi
        
        
        # Check if command exists in PATH
        local found_in_path=""
        local path_dir
        while IFS= read -r path_dir; do
            if [[ -f "$path_dir/$cmd" ]]; then
                found_in_path="$path_dir/$cmd"
                # Check if the found binary is writable
                if [[ -w "$found_in_path" ]]; then
                    log "$CRITICAL" "Writable binary in PATH: $found_in_path"
                    echo "WRITABLE_BINARY:$found_in_path"
                fi
                break
            fi
        done <<< "$(echo "$cron_path" | tr ':' '\n')"
        
        # If command not found, check if we can create it
        if [[ -z "$found_in_path" ]]; then
            while IFS= read -r path_dir; do
                if [[ -w "$path_dir" ]] 2>/dev/null; then
                    log "$CRITICAL" "Missing binary '$cmd' - can create in writable PATH: $path_dir"
                    echo "MISSING_BINARY:$cmd:$path_dir"
                fi
            done <<< "$(echo "$cron_path" | tr ':' '\n')"
        fi
    done < "$temp_commands"
    
    # Check PATH directories for write access
    local path_dir
    while IFS= read -r path_dir; do
        if [[ -w "$path_dir" ]] 2>/dev/null; then
            log "$CRITICAL" "Writable PATH directory: $path_dir"
            echo "WRITABLE_PATH:$path_dir"
        fi
    done <<< "$(echo "$cron_path" | tr ':' '\n')"
    
    rm -f "$temp_commands"
}

#=============================================================================
# SCRIPT ANALYSIS AND DEPENDENCY EXTRACTION
#=============================================================================

extract_script_dependencies() {
    local script_file="$1"
    
    # Only analyze readable files
    if [[ ! -r "$script_file" ]]; then
        return
    fi
    
    local temp_deps
    temp_deps=$(mktemp)
    
    # Only analyze text files to avoid binary data
    if ! file "$script_file" 2>/dev/null | grep -q "text"; then
        return
    fi
    
    # Determine script type and extract dependencies accordingly
    local shebang
    shebang=$(head -1 "$script_file" 2>/dev/null | tr -d '\0')
    
    # Shell scripts
    if [[ "$shebang" =~ (bash|sh|zsh|dash) || "$script_file" =~ \.(sh|bash)$ ]]; then
        # Source/include statements (more compatible regex)
        grep -a -oE 'source[[:space:]]+[^;[:space:]|]+|\.[[:space:]]+[^;[:space:]|]+' "$script_file" 2>/dev/null | awk '{print $NF}' >> "$temp_deps" || true
        
        # Configuration files
        grep -a -oE '\-f[[:space:]]+[^;[:space:]|]+|\-\-config[=[:space:]]+[^;[:space:]|]+' "$script_file" 2>/dev/null | awk '{print $NF}' | tr -d "\"'" >> "$temp_deps" || true
        
        # File operations (more compatible regex)
        grep -a -oE 'cat[[:space:]]+[^;[:space:]|]+|>[[:space:]]*[^;[:space:]|]+|<[[:space:]]+[^;[:space:]|]+' "$script_file" 2>/dev/null | awk '{print $NF}' | grep -v '^>' | tr -d "\"'" >> "$temp_deps" || true
    fi
    
    # Python scripts
    if [[ "$shebang" =~ python || "$script_file" =~ \.py$ ]]; then
        grep -a -oE 'import[[:space:]]+[^;[:space:]]+|from[[:space:]]+[^;[:space:]]+' "$script_file" 2>/dev/null | awk '{print $NF}' | sed 's/\.py$//' >> "$temp_deps" || true
        grep -oE 'open\(['"'"'"][^'"'"'"]+['"'"'"]' "$script_file" 2>/dev/null | sed -E 's/open\(['"'"'"]([^'"'"'"]+)['"'"'"].*/\1/' >> "$temp_deps" || true
    fi
    
    # Filter and clean dependencies
    sort -u "$temp_deps" 2>/dev/null | while read -r dep; do
        if [[ -z "$dep" || "$dep" =~ ^[[:space:]]*$ || "$dep" =~ ^[0-9]+$ || "$dep" == "--" || "$dep" == "-" ]]; then
            continue
        fi
        # Remove quotes and clean path
        dep=$(echo "$dep" | tr -d "\"'" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        # Skip common flags and single characters
        if [[ ${#dep} -gt 2 && ! "$dep" =~ ^- ]]; then
            echo "$dep"
        fi
    done
    
    rm -f "$temp_deps"
}

#=============================================================================
# CORE ANALYSIS ENGINE - RECURSIVE SCRIPT ANALYZER
#=============================================================================

analyze_cron_entry_chain() {
    local cron_entry="$1"
    local depth="$2"
    local max_depth=3
    
    # Prevent infinite loops and excessive depth
    if [[ $depth -gt $max_depth ]]; then
        return
    fi
    
    
    # Parse cron entry format: TYPE:SOURCE:COMMAND
    IFS=':' read -r entry_type entry_source entry_command <<< "$cron_entry"
    
    # Extract the actual command/script from cron entry
    local script_path=""
    case "$entry_type" in
        "SYSTEM"|"CROND"|"USER")
            # Skip time fields (5) and user field (1) = 6 fields total
            script_path=$(echo "$entry_command" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//')
            ;;
        "RUNPARTS"|"SYSTEMD")
            script_path="$entry_command"
            ;;
    esac
    
    if [[ -z "$script_path" ]]; then
        return
    fi
    
    
    # Check if using relative paths (PATH injection opportunity)
    local first_word
    first_word=$(echo "$script_path" | awk '{print $1}')
    if [[ ! "$first_word" =~ ^(/|\./|~/|\$) ]]; then
        log "$CRITICAL" "Found relative path in cron job: $first_word"
        VULNERABILITIES["PATH_INJECTION_${depth}_${first_word}"]="$cron_entry"
        
        # Analyze PATH injection for this command
        local temp_script
        temp_script=$(mktemp)
        echo "$script_path" > "$temp_script"
        local path_vulns
        path_vulns=$(analyze_path_injection "$temp_script" "/usr/bin:/bin")
        if [[ -n "$path_vulns" ]]; then
            echo -e "${RED}[CRITICAL] PATH injection: $path_vulns${NC}"
        fi
        rm -f "$temp_script"
    fi
    
    # Find the actual script file
    local actual_script_file=""
    if [[ -f "$first_word" ]]; then
        actual_script_file="$first_word"
    elif [[ "$first_word" =~ ^/ ]] && [[ -f "$first_word" ]]; then
        actual_script_file="$first_word"
    else
        # Try to find the script in common locations
        for prefix in "" "/usr/bin/" "/bin/" "/usr/local/bin/" "/opt/"; do
            if [[ -f "${prefix}${first_word}" ]]; then
                actual_script_file="${prefix}${first_word}"
                break
            fi
        done
    fi
    
    # Analyze the script file if found
    if [[ -n "$actual_script_file" ]]; then
        # Avoid reanalyzing the same file
        if [[ -n "${ANALYZED_FILES[$actual_script_file]:-}" ]]; then
            return
        fi
        ANALYZED_FILES["$actual_script_file"]=1
        
        
        # Check write access to the script
        analyze_script_write_access "$actual_script_file" "$depth"
        
        # PATH injection analysis for the script
        analyze_script_path_injection "$actual_script_file" "$depth"
        
        # Extract and analyze dependencies
        analyze_script_dependencies "$actual_script_file" "$depth"
    fi
}

analyze_script_write_access() {
    local script_file="$1"
    local depth="$2"
    
    local write_results
    write_results=$(check_write_access "$script_file")
    if [[ -n "$write_results" ]]; then
        log "$CRITICAL" "Write access vulnerabilities for $script_file:"
        while read -r vuln; do
            log "$CRITICAL" "  -> $vuln"
            VULNERABILITIES["WRITE_ACCESS_${depth}_$(basename "$script_file")"]="$vuln"
        done <<< "$write_results"
    fi
}

analyze_script_path_injection() {
    local script_file="$1"
    local depth="$2"
    
    local path_results
    path_results=$(analyze_path_injection "$script_file")
    if [[ -n "$path_results" ]]; then
        log "$CRITICAL" "PATH injection vulnerabilities in $script_file:"
        while read -r vuln; do
            log "$CRITICAL" "  -> $vuln"
            VULNERABILITIES["PATH_INJECTION_${depth}_$(basename "$script_file")"]="$vuln"
        done <<< "$path_results"
    fi
}

analyze_script_dependencies() {
    local script_file="$1"
    local depth="$2"
    
    local dependencies
    dependencies=$(extract_script_dependencies "$script_file")
    
    if [[ -n "$dependencies" ]]; then
        while read -r dep; do
            if [[ -z "$dep" || "$dep" =~ ^[[:space:]]*$ ]]; then
                continue
            fi
            
            # Recursively analyze each dependency
            if [[ -f "$dep" ]]; then
                analyze_cron_entry_chain "DEPENDENCY:$script_file:$dep" $((depth + 1))
            else
                # Check if dependency is a missing file we can create
                if [[ "$dep" == */* ]]; then
                    local dep_dir
                    dep_dir=$(dirname "$dep")
                    if [[ -w "$dep_dir" ]] 2>/dev/null; then
                        log "$CRITICAL" "Missing dependency in writable location: $dep"
                        VULNERABILITIES["MISSING_DEPENDENCY_${depth}_$(basename "$dep")"]="$dep in $dep_dir"
                    fi
                fi
            fi
        done <<< "$dependencies"
    fi
}

#=============================================================================
# MAIN EXECUTION
#=============================================================================

main() {
    echo -e "${CYAN}KRONMANCER v2.0 - Cron Privilege Escalation Scanner${NC}"
    echo -e "Target: $(hostname) | User: $CURRENT_USER | $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # Phase 1: Collect all cron jobs
    local all_cron_entries
    all_cron_entries=$(collect_all_cron_jobs)
    
    if [[ -z "$all_cron_entries" ]]; then
        echo "No cron jobs found or insufficient permissions"
        exit 0
    fi
    
    # Phase 2: Analyze each cron job entry
    while IFS= read -r cron_entry; do
        if [[ -z "$cron_entry" ]]; then
            continue
        fi
        
        
        # Core recursive analysis
        analyze_cron_entry_chain "$cron_entry" 1
        
    done <<< "$all_cron_entries"
    
    echo -e "\n${GREEN}SCAN COMPLETE - Vulnerabilities found: ${#VULNERABILITIES[@]}${NC}"
    
    # Display summary
    if [[ ${#VULNERABILITIES[@]} -gt 0 ]]; then
        echo -e "${RED}VULNERABILITIES DISCOVERED:${NC}"
        for vuln_key in "${!VULNERABILITIES[@]}"; do
            echo -e "${RED}[!] $vuln_key: ${VULNERABILITIES[$vuln_key]}${NC}"
        done
    else
        echo -e "${GREEN}No privilege escalation vulnerabilities found${NC}"
    fi
}

# Trap for cleanup
trap 'echo -e "\n${RED}Scan interrupted${NC}"; exit 1' INT TERM

# Execute main function
main "$@"