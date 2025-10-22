#!/usr/bin/env bash

# ⚠️  WARNING: This script is for local demo/testing only.
# ⚠️  Do NOT use it to misrepresent actual work or falsify commit history.
# ⚠️  Backdating commits can mislead collaborators and violate repository policies.

set -euo pipefail

# ============================================================================
# CONFIGURATION & DEFAULTS
# ============================================================================

START_DATE=""
END_DATE=""
USERS=""
AVG_PER_WEEK=2
SEED=42
DRY_RUN=false
PUSH=false

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Generate realistic backdated Git commits for demo/testing purposes.

Required Options:
  --start DATE              Start date (YYYY-MM-DD)
  --end DATE                End date (YYYY-MM-DD)
  --users "Name Email,..."  Comma-separated list of "Name email@example.com"

Optional:
  --avg-per-week N          Average commits per week (default: 2)
  --seed N                  Random seed for reproducibility (default: 42)
  --dry-run                 Print plan without creating commits
  --push                    Push commits after generation (with confirmation)
  -h, --help                Show this help message

Example:
  $0 --start 2025-09-11 --end 2025-10-28 \\
     --users "Devesh Sawant deveshsawant05@gmail.com,Aadi Aadisinghal0591@gmail.com" \\
     --avg-per-week 2 --seed 100

EOF
    exit 1
}

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
}

error() {
    log "ERROR: $*"
    exit 1
}

validate_date() {
    local date_str="$1"
    if ! date -d "$date_str" &>/dev/null 2>&1; then
        if ! date -j -f "%Y-%m-%d" "$date_str" &>/dev/null 2>&1; then
            error "Invalid date format: $date_str (expected YYYY-MM-DD)"
        fi
    fi
}

# ============================================================================
# PARSE ARGUMENTS
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --start)
            START_DATE="$2"
            shift 2
            ;;
        --end)
            END_DATE="$2"
            shift 2
            ;;
        --users)
            USERS="$2"
            shift 2
            ;;
        --avg-per-week)
            AVG_PER_WEEK="$2"
            shift 2
            ;;
        --seed)
            SEED="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --push)
            PUSH=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Validate required parameters
[[ -z "$START_DATE" ]] && error "Missing required parameter: --start"
[[ -z "$END_DATE" ]] && error "Missing required parameter: --end"
[[ -z "$USERS" ]] && error "Missing required parameter: --users"

validate_date "$START_DATE"
validate_date "$END_DATE"

# ============================================================================
# INITIALIZE GIT REPOSITORY
# ============================================================================

if [[ ! -d .git ]]; then
    log "No .git directory found. Initializing repository..."
    if [[ "$DRY_RUN" == false ]]; then
        git init
        log "Git repository initialized."
    else
        log "[DRY RUN] Would initialize git repository"
    fi
fi

# ============================================================================
# PARSE USERS
# ============================================================================

declare -a USER_NAMES=()
declare -a USER_EMAILS=()

IFS=',' read -ra USER_ARRAY <<< "$USERS"
for user_entry in "${USER_ARRAY[@]}"; do
    # Extract name and email
    if [[ "$user_entry" =~ ^(.+)[[:space:]]([^[:space:]]+@[^[:space:]]+)$ ]]; then
        USER_NAMES+=("${BASH_REMATCH[1]}")
        USER_EMAILS+=("${BASH_REMATCH[2]}")
    else
        error "Invalid user format: '$user_entry' (expected 'Name email@example.com')"
    fi
done

log "Parsed ${#USER_NAMES[@]} user(s)"

# ============================================================================
# COLLECT PROJECT FILES
# ============================================================================

log "Collecting project files..."

declare -a FILES=()

# Exclude patterns
EXCLUDE_PATTERNS=(
    ".git"
    "node_modules"
    "dist"
    "build"
    ".next"
    "coverage"
    "__pycache__"
    "*.pyc"
    ".DS_Store"
    "*.swp"
    "*.swo"
    ".vscode"
    ".idea"
    "bin"
    "obj"
    "*.o"
    "*.so"
    "*.a"
    "*.exe"
)

# Build find exclude expression
FIND_EXCLUDE=""
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    FIND_EXCLUDE="$FIND_EXCLUDE -name '$pattern' -prune -o"
done

# Collect files
while IFS= read -r -d '' file; do
    FILES+=("$file")
done < <(eval "find . $FIND_EXCLUDE -type f -print0")

if [[ ${#FILES[@]} -eq 0 ]]; then
    error "No files found to commit!"
fi

log "Found ${#FILES[@]} files to commit"

# ============================================================================
# SHUFFLE FILES (deterministic with seed)
# ============================================================================

# Use seed for reproducibility
RANDOM=$SEED

# Fisher-Yates shuffle
for ((i=${#FILES[@]}-1; i>0; i--)); do
    j=$((RANDOM % (i+1)))
    tmp="${FILES[i]}"
    FILES[i]="${FILES[j]}"
    FILES[j]="$tmp"
done

# ============================================================================
# GENERATE COMMIT TIMELINE
# ============================================================================

log "Generating commit timeline..."

# Calculate date range in days
if date -v +1d &>/dev/null 2>&1; then
    # BSD date (macOS)
    START_EPOCH=$(date -j -f "%Y-%m-%d" "$START_DATE" "+%s")
    END_EPOCH=$(date -j -f "%Y-%m-%d" "$END_DATE" "+%s")
else
    # GNU date (Linux)
    START_EPOCH=$(date -d "$START_DATE" "+%s")
    END_EPOCH=$(date -d "$END_DATE" "+%s")
fi

TOTAL_DAYS=$(( (END_EPOCH - START_EPOCH) / 86400 ))
TOTAL_WEEKS=$(( (TOTAL_DAYS + 6) / 7 ))
TARGET_COMMITS=$(( TOTAL_WEEKS * AVG_PER_WEEK ))

# Cap at number of files
if [[ $TARGET_COMMITS -gt ${#FILES[@]} ]]; then
    TARGET_COMMITS=${#FILES[@]}
fi

log "Date range: $START_DATE to $END_DATE ($TOTAL_DAYS days)"
log "Target commits: $TARGET_COMMITS"

declare -a COMMIT_DATES=()
declare -a COMMIT_AUTHORS=()
declare -a COMMIT_MESSAGES=()
declare -a COMMIT_FILES_START=()
declare -a COMMIT_FILES_COUNT=()

# Generate commit dates
for ((i=0; i<TARGET_COMMITS; i++)); do
    # Random day within range (weekday bias: 70% Mon-Fri, 30% Sat-Sun)
    day_offset=$((RANDOM % TOTAL_DAYS))
    
    if date -v +1d &>/dev/null 2>&1; then
        # BSD date
        commit_date=$(date -j -v +${day_offset}d -f "%Y-%m-%d" "$START_DATE" "+%Y-%m-%d")
        day_of_week=$(date -j -f "%Y-%m-%d" "$commit_date" "+%u")
    else
        # GNU date
        commit_date=$(date -d "$START_DATE + $day_offset days" "+%Y-%m-%d")
        day_of_week=$(date -d "$commit_date" "+%u")
    fi
    
    # Weekday bias
    if [[ $day_of_week -ge 6 ]]; then
        # Weekend - 30% chance
        if [[ $((RANDOM % 100)) -lt 30 ]]; then
            :  # Keep this date
        else
            # Try to move to a weekday
            adjustment=$((RANDOM % 3 - 1))  # -1, 0, or 1
            day_offset=$((day_offset + adjustment))
            if [[ $day_offset -lt 0 ]]; then day_offset=0; fi
            if [[ $day_offset -ge $TOTAL_DAYS ]]; then day_offset=$((TOTAL_DAYS - 1)); fi
            
            if date -v +1d &>/dev/null 2>&1; then
                commit_date=$(date -j -v +${day_offset}d -f "%Y-%m-%d" "$START_DATE" "+%Y-%m-%d")
            else
                commit_date=$(date -d "$START_DATE + $day_offset days" "+%Y-%m-%d")
            fi
        fi
    fi
    
    # Random time between 09:00 and 20:00
    hour=$((RANDOM % 12 + 9))
    minute=$((RANDOM % 60))
    second=$((RANDOM % 60))
    
    commit_datetime="$commit_date $hour:$minute:$second"
    COMMIT_DATES+=("$commit_datetime")
    
    # Random author
    author_idx=$((RANDOM % ${#USER_NAMES[@]}))
    COMMIT_AUTHORS+=("$author_idx")
done

# Sort commits by date
declare -a SORTED_INDICES=()
for ((i=0; i<${#COMMIT_DATES[@]}; i++)); do
    SORTED_INDICES+=("$i")
done

# Bubble sort by date (simple, works for our use case)
for ((i=0; i<${#SORTED_INDICES[@]}; i++)); do
    for ((j=i+1; j<${#SORTED_INDICES[@]}; j++)); do
        idx_i=${SORTED_INDICES[i]}
        idx_j=${SORTED_INDICES[j]}
        
        if date -v +1d &>/dev/null 2>&1; then
            epoch_i=$(date -j -f "%Y-%m-%d %H:%M:%S" "${COMMIT_DATES[idx_i]}" "+%s")
            epoch_j=$(date -j -f "%Y-%m-%d %H:%M:%S" "${COMMIT_DATES[idx_j]}" "+%s")
        else
            epoch_i=$(date -d "${COMMIT_DATES[idx_i]}" "+%s")
            epoch_j=$(date -d "${COMMIT_DATES[idx_j]}" "+%s")
        fi
        
        if [[ $epoch_i -gt $epoch_j ]]; then
            tmp=${SORTED_INDICES[i]}
            SORTED_INDICES[i]=${SORTED_INDICES[j]}
            SORTED_INDICES[j]=$tmp
        fi
    done
done

# ============================================================================
# DISTRIBUTE FILES ACROSS COMMITS
# ============================================================================

COMMIT_TYPES=("feat" "fix" "docs" "chore" "refactor" "test")
file_idx=0

for ((i=0; i<${#SORTED_INDICES[@]}; i++)); do
    idx=${SORTED_INDICES[i]}
    
    # Each commit gets 1-3 files
    files_in_commit=$((RANDOM % 3 + 1))
    
    # Don't exceed available files
    if [[ $((file_idx + files_in_commit)) -gt ${#FILES[@]} ]]; then
        files_in_commit=$((${#FILES[@]} - file_idx))
    fi
    
    if [[ $files_in_commit -le 0 ]]; then
        break
    fi
    
    COMMIT_FILES_START[idx]=$file_idx
    COMMIT_FILES_COUNT[idx]=$files_in_commit
    
    # Generate commit message
    commit_type=${COMMIT_TYPES[$((RANDOM % ${#COMMIT_TYPES[@]}))]}
    
    # Determine scope from first file
    first_file="${FILES[file_idx]}"
    scope=""
    
    if [[ "$first_file" =~ src/ ]]; then
        scope="core"
    elif [[ "$first_file" =~ test/ ]]; then
        scope="tests"
    elif [[ "$first_file" =~ doc/ ]]; then
        scope="docs"
    elif [[ "$first_file" =~ example/ ]]; then
        scope="examples"
    elif [[ "$first_file" =~ \.md$ ]]; then
        scope="docs"
    elif [[ "$first_file" =~ Makefile|Dockerfile|docker-compose ]]; then
        scope="build"
    elif [[ "$first_file" =~ \.c$|\.h$ ]]; then
        scope="core"
    fi
    
    # Generate description
    filename=$(basename "$first_file")
    filename_noext="${filename%.*}"
    
    if [[ $files_in_commit -eq 1 ]]; then
        description="add $filename_noext"
    else
        description="add $filename_noext and $((files_in_commit - 1)) more"
    fi
    
    if [[ -n "$scope" ]]; then
        message="$commit_type($scope): $description"
    else
        message="$commit_type: $description"
    fi
    
    COMMIT_MESSAGES[idx]="$message"
    
    file_idx=$((file_idx + files_in_commit))
done

# ============================================================================
# CREATE COMMITS OR PRINT PLAN
# ============================================================================

declare -A AUTHOR_COMMIT_COUNT

if [[ "$DRY_RUN" == true ]]; then
    log "DRY RUN - Commit Plan:"
    echo ""
    printf "%-20s %-30s %-50s %s\n" "DATE" "AUTHOR" "MESSAGE" "FILES"
    printf "%s\n" "$(printf '=%.0s' {1..130})"
fi

for ((i=0; i<${#SORTED_INDICES[@]}; i++)); do
    idx=${SORTED_INDICES[i]}
    
    commit_date="${COMMIT_DATES[idx]}"
    author_idx=${COMMIT_AUTHORS[idx]}
    author_name="${USER_NAMES[author_idx]}"
    author_email="${USER_EMAILS[author_idx]}"
    message="${COMMIT_MESSAGES[idx]}"
    files_start=${COMMIT_FILES_START[idx]:-0}
    files_count=${COMMIT_FILES_COUNT[idx]:-0}
    
    if [[ $files_count -eq 0 ]]; then
        continue
    fi
    
    # Track author stats
    AUTHOR_COMMIT_COUNT["$author_name"]=$((${AUTHOR_COMMIT_COUNT["$author_name"]:-0} + 1))
    
    # Collect files for this commit
    commit_files=()
    for ((j=0; j<files_count; j++)); do
        commit_files+=("${FILES[files_start + j]}")
    done
    
    if [[ "$DRY_RUN" == true ]]; then
        files_str=$(IFS=', '; echo "${commit_files[*]}")
        printf "%-20s %-30s %-50s %s\n" "$commit_date" "$author_name" "$message" "$files_str"
    else
        # Stage files
        for file in "${commit_files[@]}"; do
            git add "$file" 2>/dev/null || true
        done
        
        # Create commit with backdated timestamp
        export GIT_AUTHOR_NAME="$author_name"
        export GIT_AUTHOR_EMAIL="$author_email"
        export GIT_COMMITTER_NAME="$author_name"
        export GIT_COMMITTER_EMAIL="$author_email"
        export GIT_AUTHOR_DATE="$commit_date"
        export GIT_COMMITTER_DATE="$commit_date"
        
        git commit -m "$message" --date="$commit_date" >/dev/null 2>&1 || true
        
        log "Commit $((i+1))/${#SORTED_INDICES[@]}: $message"
    fi
done

# ============================================================================
# PRINT SUMMARY
# ============================================================================

echo ""
echo "================================================================================"
echo "SUMMARY"
echo "================================================================================"

if [[ "$DRY_RUN" == true ]]; then
    echo "Mode:             DRY RUN (no commits created)"
else
    echo "Mode:             LIVE (commits created)"
fi

total_commits=0
for count in "${AUTHOR_COMMIT_COUNT[@]}"; do
    total_commits=$((total_commits + count))
done

echo "Total commits:    $total_commits"
echo "Date range:       $START_DATE to $END_DATE"
echo ""
echo "Commits per author:"
for author_name in "${!AUTHOR_COMMIT_COUNT[@]}"; do
    printf "  %-30s %d\n" "$author_name" "${AUTHOR_COMMIT_COUNT[$author_name]}"
done
echo "================================================================================"

# ============================================================================
# PUSH (optional)
# ============================================================================

if [[ "$PUSH" == true ]] && [[ "$DRY_RUN" == false ]]; then
    echo ""
    read -p "⚠️  Push commits to remote? This will alter remote history! [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Pushing commits..."
        git push --force
        log "Push complete."
    else
        log "Push cancelled."
    fi
fi

log "Done!"
