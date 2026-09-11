#!/usr/bin/env bash
#
# refreshOCSPHosts.sh - regenerate the OCSP responder blocklist from https://crt.sh/
#
# Reads the crt.sh OCSP responder table, extracts the responder hostnames,
# normalizes and validates them, applies the exclude list, and writes a
# hosts-format blocklist. The write is atomic and gated on sanity checks so a
# truncated or error response cannot clobber a good list.
#
# Run this at the base directory of your repo.
#
# Usage:
#   scripts/refreshOCSPHosts.sh [options]
#
# Options:
#   -o, --output FILE     blocklist to write (default: ocsp-hosts)
#   -e, --exclude FILE    exclude patterns, one ERE per line, '#' starts a
#                         comment (default: exclude.txt)
#   -s, --source URL      crt.sh responder page
#                         (default: https://crt.sh/ocsp-responders)
#   -a, --address ADDR    sinkhole address to prefix (default: 0.0.0.0)
#   -t, --timeout SECS    per-attempt download timeout (default: 180)
#   -r, --retries N       download attempts after the first; crt.sh returns 502
#                         in bursts, so these use exponential backoff bounded to
#                         300s total. 0 fails fast (default: 8)
#   -m, --min-hosts N     fail if fewer than N hosts survive (default: 500)
#   -S, --max-shrink PCT  fail if the list shrinks by more than PCT
#                         (default: 10)
#   -p, --pull            git pull before writing; refuses on a dirty tree
#   -f, --force           bypass the min-hosts and max-shrink gates
#   -n, --dryrun          report what would change, write nothing
#   -v, --verbose         step-level progress on stderr
#   -h, --help            show this help
#
# Output:
#   stdout carries a key=value summary - changed, hosts, added, removed,
#   excluded, output - suitable for appending to $GITHUB_OUTPUT. Progress,
#   warnings and errors go to stderr.
#
# Exit status:
#   0  success (list written, or already up to date)
#   1  usage or runtime error
#   2  sanity gate tripped; the existing list was left untouched
#
set -euo pipefail
IFS=$'\n\t'

readonly PROGRAM="${0##*/}"

OUTPUT='ocsp-hosts'
EXCLUDE_FILE='exclude.txt'
SOURCE_URL='https://crt.sh/ocsp-responders'
SINK_ADDRESS='0.0.0.0'
TIMEOUT=180
RETRIES=8
MIN_HOSTS=500

# Bound on the whole retry sequence, not each attempt. crt.sh rejects with a
# fast 502 while it is overloaded, so the backoff needs room to outlast a burst.
readonly RETRY_MAX_TIME=300
MAX_SHRINK=10
DO_PULL=0
FORCE=0
DRYRUN=0
VERBOSE=0

if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
	readonly C_RESET=$'\033[0m' C_INFO=$'\033[36m' C_WARN=$'\033[33m' C_ERR=$'\033[31m' C_OK=$'\033[32m'
else
	readonly C_RESET='' C_INFO='' C_WARN='' C_ERR='' C_OK=''
fi

log() {
	((VERBOSE)) && printf '%s==>%s %s\n' "$C_INFO" "$C_RESET" "$*" >&2
	return 0
}
ok() { printf '%s%s%s\n' "$C_OK" "$*" "$C_RESET" >&2; }
warn() { printf '%swarning:%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
die() {
	printf '%s%s: error:%s %s\n' "$C_ERR" "$PROGRAM" "$C_RESET" "$1" >&2
	exit "${2:-1}"
}

usage() {
	awk 'NR > 2 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"
}

require_int() {
	[[ $2 =~ ^[0-9]+$ ]] || die "$1 expects a non-negative integer, got '$2'"
	[[ -z ${3:-} || $2 -le $3 ]] || die "$1 must not exceed $3, got '$2'"
}

while (($#)); do
	case $1 in
	-o | --output)
		OUTPUT=${2:?--output needs a value}
		shift 2
		;;
	-e | --exclude)
		EXCLUDE_FILE=${2:?--exclude needs a value}
		shift 2
		;;
	-s | --source)
		SOURCE_URL=${2:?--source needs a value}
		shift 2
		;;
	-a | --address)
		SINK_ADDRESS=${2:?--address needs a value}
		shift 2
		;;
	-t | --timeout)
		require_int --timeout "${2:-}"
		TIMEOUT=$2
		shift 2
		;;
	-r | --retries)
		require_int --retries "${2:-}"
		RETRIES=$2
		shift 2
		;;
	-m | --min-hosts)
		require_int --min-hosts "${2:-}"
		MIN_HOSTS=$2
		shift 2
		;;
	-S | --max-shrink)
		require_int --max-shrink "${2:-}" 100
		MAX_SHRINK=$2
		shift 2
		;;
	-p | --pull)
		DO_PULL=1
		shift
		;;
	-f | --force)
		FORCE=1
		shift
		;;
	-n | --dryrun | --dry-run)
		DRYRUN=1
		shift
		;;
	-v | --verbose)
		VERBOSE=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	--)
		shift
		break
		;;
	*) die "unknown argument '$1' (try --help)" ;;
	esac
done
(($# == 0)) || die "unexpected operand '$1' (try --help)"

for tool in curl sed awk sort comm grep mktemp; do
	command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
done

# The address is spliced into a sed replacement, so keep it to the characters
# an IPv4 or IPv6 literal can contain.
[[ $SINK_ADDRESS =~ ^[0-9a-fA-F.:]+$ ]] ||
	die "--address must be an IPv4 or IPv6 literal, got '$SINK_ADDRESS'"

OUT_DIR=${OUTPUT%/*}
[[ $OUT_DIR == "$OUTPUT" ]] && OUT_DIR='.'
readonly OUT_DIR
[[ -d $OUT_DIR ]] || die "output directory does not exist: $OUT_DIR"
[[ -w $OUT_DIR ]] || die "output directory is not writable: $OUT_DIR"

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ocsp-hosts.XXXXXX")
readonly WORK_DIR
STAGED=''
cleanup() {
	rm -rf -- "$WORK_DIR"
	[[ -n $STAGED ]] && rm -f -- "$STAGED"
	return 0
}
trap cleanup EXIT INT TERM

if ((DO_PULL)); then
	log 'refreshing the working tree'
	git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die '--pull requires a git working tree'
	[[ -z $(git status --porcelain -- "$OUTPUT") ]] ||
		die "--pull refused: '$OUTPUT' has uncommitted changes"
	git pull --ff-only || die 'git pull failed; resolve the working tree by hand'
fi

readonly RAW="$WORK_DIR/raw.html"
log "downloading $SOURCE_URL"
# Pin the transport for the real source; a local mirror passed via --source is
# allowed but flagged, because its content is unauthenticated.
transport=('--proto' '=https' '--tlsv1.2')
if [[ $SOURCE_URL != https://* ]]; then
	transport=()
	warn "source is not https, content is unauthenticated: $SOURCE_URL"
fi
# Omitting --retry-delay leaves curl's exponential backoff in place, which
# outlasts a 502 burst far better than a short fixed delay. --max-time applies
# per attempt; --retry-max-time bounds the sequence.
#
# --retry-all-errors is required, not belt-and-braces: an overloaded crt.sh
# tears down the connection as it sends the 502, so curl reports a receive
# failure (exit 56) rather than an HTTP status. That is not in curl's default
# transient-error set, so without this flag the retries never fire at all.
#
# Keep curl's retry warnings visible when verbose, since a long backoff
# otherwise looks like a hang.
quiet=('--silent')
((VERBOSE)) && quiet=('--no-progress-meter')
# crt.sh serves this page uncompressed unless asked: gzip takes it from ~9.5MB
# to ~0.5MB. It offers neither brotli nor zstd, and --compressed advertises
# whatever the local libcurl supports, so there is nothing to hand-tune here.
curl --fail "${quiet[@]}" --show-error --location --compressed \
	${transport[@]+"${transport[@]}"} \
	--max-time "$TIMEOUT" \
	--retry "$RETRIES" --retry-all-errors --retry-max-time "$RETRY_MAX_TIME" \
	--user-agent "$PROGRAM (+https://github.com/jauderho/ocsp-hosts)" \
	--output "$RAW" "$SOURCE_URL" ||
	die "download failed: $SOURCE_URL"

[[ -s $RAW ]] || die "download produced an empty response: $SOURCE_URL"
grep -qF '<A title="' "$RAW" ||
	die "response does not look like the crt.sh responder table: $SOURCE_URL"
log "downloaded $(wc -c <"$RAW" | tr -d '[:space:]') bytes"

# The anchor *text* on crt.sh is truncated with an ellipsis for long URLs; the
# title attribute carries the full value, so parse that instead.
#
# The grep is a prefilter, not redundant: it drops ~97% of the 200k lines with a
# literal scan so sed's regex only runs on the few thousand that can match,
# which measures 2.4x faster than sed alone over the whole page.
readonly HOSTS="$WORK_DIR/hosts"
grep -F '<A title="' "$RAW" |
	sed -n 's/.*<A title="\([^"]*\)".*/\1/p' |
	awk '
	{
		h = $0
		gsub(/^[ \t]+|[ \t]+$/, "", h)   # surrounding whitespace
		sub(/^\$+/, "", h)               # stray leading sigil
		sub(/^[Uu][Rr][IiLl][:=]+/, "", h)  # URI: / URL= / uri= prefixes
		sub(/^[^:\/?#]*:\/\//, "", h)    # scheme, including the "hhtp" typo
		sub(/^[^\/@]*@/, "", h)          # userinfo
		sub(/[\/?#].*$/, "", h)          # path, query, fragment
		sub(/:[0-9]*$/, "", h)           # port
		sub(/\.$/, "", h)                # root label
		h = tolower(h)
		if (length(h) < 4 || length(h) > 253)
			next
		# Keep only syntactically valid multi-label hostnames. An alphabetic
		# TLD also rejects bare IPv4 literals; anything bracketed, LDAP DNs
		# and other junk fail the character class.
		if (h ~ /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/)
			print h
	}' |
	LC_ALL=C sort -u >"$HOSTS"

parsed=$(wc -l <"$HOSTS")
parsed=${parsed//[[:space:]]/}
log "parsed $parsed unique hostnames"
((parsed > 0)) || die 'no hostnames survived parsing; the crt.sh page layout may have changed'

# Exclude list: one extended regex per line, '#' comments and blanks ignored.
readonly PATTERNS="$WORK_DIR/patterns"
readonly KEPT="$WORK_DIR/kept"
if [[ -e $EXCLUDE_FILE ]]; then
	# Failing to read the exclude list would silently publish hosts the user
	# asked to keep out, so treat it as an error rather than an empty list.
	[[ -f $EXCLUDE_FILE && -r $EXCLUDE_FILE ]] ||
		die "exclude file is not a readable file: $EXCLUDE_FILE"
	sed -e 's/[[:space:]]*#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
		"$EXCLUDE_FILE" >"$WORK_DIR/patterns.raw" ||
		die "failed to read $EXCLUDE_FILE"
	grep -v '^$' "$WORK_DIR/patterns.raw" >"$PATTERNS" || :
fi
if [[ -s $PATTERNS ]]; then
	log "applying $(wc -l <"$PATTERNS" | tr -d '[:space:]') exclude pattern(s) from $EXCLUDE_FILE"
	set +e
	grep -Evf "$PATTERNS" "$HOSTS" >"$KEPT"
	status=$?
	set -e
	((status <= 1)) || die "failed to apply exclude patterns from $EXCLUDE_FILE"
else
	log "no exclude patterns to apply"
	cp -- "$HOSTS" "$KEPT"
fi

kept=$(wc -l <"$KEPT")
kept=${kept//[[:space:]]/}
excluded=$((parsed - kept))
((excluded == 0)) || log "excluded $excluded hostname(s)"

# Sanity gates. A crt.sh outage or a layout change must not silently empty the
# blocklist, so refuse to write an implausibly small list.
readonly PREVIOUS="$WORK_DIR/previous"
previous=0
if [[ -f $OUTPUT ]]; then
	sed -n 's/^[^[:space:]]*[[:space:]]\{1,\}\([^[:space:]]\{1,\}\)[[:space:]]*$/\1/p' \
		"$OUTPUT" | LC_ALL=C sort -u >"$PREVIOUS"
	previous=$(wc -l <"$PREVIOUS")
	previous=${previous//[[:space:]]/}
else
	: >"$PREVIOUS"
	log "$OUTPUT does not exist yet; skipping the shrink check"
fi

if ((kept < MIN_HOSTS)); then
	((FORCE)) || die "only $kept hosts, below the --min-hosts floor of $MIN_HOSTS" 2
	warn "only $kept hosts, below the --min-hosts floor of $MIN_HOSTS (--force)"
fi
if ((previous > 0 && kept * 100 < previous * (100 - MAX_SHRINK))); then
	msg="list shrank from $previous to $kept hosts, more than --max-shrink ${MAX_SHRINK}%"
	((FORCE)) || die "$msg" 2
	warn "$msg (--force)"
fi

added=$(comm -13 "$PREVIOUS" "$KEPT" | wc -l)
removed=$(comm -23 "$PREVIOUS" "$KEPT" | wc -l)
added=${added//[[:space:]]/}
removed=${removed//[[:space:]]/}

if ((VERBOSE)); then
	comm -13 "$PREVIOUS" "$KEPT" | sed 's/^/    + /' >&2
	comm -23 "$PREVIOUS" "$KEPT" | sed 's/^/    - /' >&2
fi

# Machine-readable summary on stdout; all human output goes to stderr. The
# key=value form can be appended to $GITHUB_OUTPUT verbatim.
emit_summary() {
	printf 'changed=%s\nhosts=%s\nadded=%s\nremoved=%s\nexcluded=%s\noutput=%s\n' \
		"$1" "$kept" "$added" "$removed" "$excluded" "$OUTPUT"
}

if ((DRYRUN)); then
	if ((added == 0 && removed == 0)); then
		emit_summary false
		ok "dryrun: $OUTPUT already up to date ($kept hosts)"
	else
		emit_summary true
		ok "dryrun: would write $kept hosts (+$added / -$removed); $OUTPUT unchanged"
	fi
	exit 0
fi

# Write through a sibling temp file so a failure never leaves a partial list.
# cleanup() removes it on any early exit; mktemp is 0600, so widen it here.
STAGED=$(mktemp "$OUT_DIR/.${OUTPUT##*/}.XXXXXX")
sed "s#^#$SINK_ADDRESS #" "$KEPT" >"$STAGED" || die "failed to stage $OUTPUT"
chmod 644 "$STAGED" || die "failed to set permissions on the staged $OUTPUT"

if [[ -f $OUTPUT ]] && cmp -s "$STAGED" "$OUTPUT"; then
	emit_summary false
	ok "$OUTPUT already up to date ($kept hosts)"
	exit 0
fi

mv -f -- "$STAGED" "$OUTPUT" || die "failed to write $OUTPUT"
STAGED=''
emit_summary true
ok "wrote $OUTPUT: $kept hosts (+$added / -$removed)"
