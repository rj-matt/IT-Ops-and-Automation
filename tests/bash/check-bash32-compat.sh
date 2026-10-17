#!/usr/bin/env bash
# shellcheck disable=SC2016  # The patterns in this file are literal regexes for grep; nothing should expand.
# Flags bash 4+ (and GNU-only) constructs in shell scripts so they still run on macOS's
# bash 3.2. A pattern scan, not a parser: it complements running the scripts under a real
# bash 3.2. Comment lines are ignored.
#
#   bash tests/bash/check-bash32-compat.sh FILE...    exit 1 if anything is found
#
# Files named *-linux.sh only run on Linux, so GNU-only commands (stat -c, date -d ...) are
# allowed there; the bash 3.2 checks still apply (some Linux systems are tested with 3.2 too).
# In shared scripts, a line that only runs on Linux can be marked with a "# linux-only" comment.
set -u

found=0
check() {
    # check FILE REGEX MESSAGE
    local hits
    hits=$(grep -nE "$2" "$1" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#')
    if [ -n "$hits" ]; then
        printf '%s: %s\n' "$1" "$3"
        printf '%s\n' "$hits" | sed 's/^/    line /'
        found=1
    fi
}

check_gnu() {
    # Like check, but lines marked "# linux-only" are allowed to use GNU-only commands.
    local hits
    hits=$(grep -nE "$2" "$1" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | grep -v '# linux-only')
    if [ -n "$hits" ]; then
        printf '%s: %s\n' "$1" "$3"
        printf '%s\n' "$hits" | sed 's/^/    line /'
        found=1
    fi
}

for f in "$@"; do
    check "$f" '(declare|local|typeset)[[:space:]]+-[a-zA-Z]*A' 'associative array (bash 4)'
    check "$f" '(declare|local|typeset)[[:space:]]+-[a-zA-Z]*[nl]([[:space:]]|$)' 'nameref or lowercase attribute (bash 4.3/4)'
    check "$f" '(declare|typeset)[[:space:]]+-[a-zA-Z]*g' 'declare -g (bash 4.2)'
    check "$f" '(^|[;&|[:space:]])(mapfile|readarray)([[:space:]]|$)' 'mapfile/readarray (bash 4)'
    check "$f" '\$\{[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?(,,?|\^\^?)' 'case-modification expansion ${x,,} ${x^^} (bash 4)'
    check "$f" '\$\{[A-Za-z_][A-Za-z0-9_]*@[QEPAaKkUuL]\}' '${x@op} transformation (bash 4.4)'
    check "$f" '\|&' '|& pipe (bash 4)'
    check "$f" '&>>' '&>> redirect (bash 4)'
    check "$f" '(^|[;&|[:space:]])coproc([[:space:]]|$)' 'coproc (bash 4)'
    check "$f" ';;&|;&([[:space:]]|$)' 'case fall-through ;& / ;;& (bash 4)'
    check "$f" 'wait[[:space:]]+-n' 'wait -n (bash 4.3)'
    check "$f" "printf[[:space:]]+(-v[[:space:]]+[A-Za-z_]+[[:space:]]+)?['\"]?%\\(" "printf '%(...)T' (bash 4.2)"
    check "$f" '\$\{?EPOCH(SECONDS|REALTIME)' 'EPOCHSECONDS/EPOCHREALTIME (bash 5)'
    check "$f" '\[\[[[:space:]]+-v[[:space:]]' '[[ -v var ]] (bash 4.2)'
    check "$f" 'shopt[[:space:]]+-s[[:space:]]+(globstar|lastpipe|autocd|direxpand)' 'shopt option added in bash 4'
    check "$f" '\$\{[A-Za-z_][A-Za-z0-9_]*:[^}]*:-[0-9]' 'negative substring length (bash 4.2)'
    check "$f" 'read[[:space:]]+(-[a-zA-Z]*[[:space:]]+)*-i[[:space:]]' 'read -i (bash 4)'
    # Not a bash 4 feature, but an easy porting slip: PowerShell writes it''s, bash prints its.
    check "$f" "[A-Za-z]''[a-z]" "PowerShell-style '' quote escape (bash drops it; use '\\'' or double quotes)"
    case "$f" in *-linux.sh) continue ;; esac
    check_gnu "$f" '(^|[;&|[:space:]])(timeout|readlink[[:space:]]+-f|realpath|sed[[:space:]]+-i|stat[[:space:]]+-c|date[[:space:]]+-d|grep[[:space:]]+-P)([[:space:]]|$)' 'GNU-only command/flag (missing or different on macOS)'
done

if [ "$found" -eq 0 ]; then printf 'No bash 4+ or GNU-only constructs found in %s file(s).\n' "$#"; fi
exit "$found"
