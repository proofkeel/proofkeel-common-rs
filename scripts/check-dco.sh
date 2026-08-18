#!/bin/sh
set -eu

usage() {
    echo "usage: $0 --message-file <path> | --history <revision>" >&2
    exit 2
}

has_valid_signoff() {
    git interpret-trailers --parse |
        grep -Eiq '^Signed-off-by:[[:space:]]+.+[[:space:]]+<[^<>[:space:]]+@[^<>[:space:]]+>$'
}

check_message_file() {
    message_file=$1
    if [ ! -f "$message_file" ]; then
        echo "DCO check: commit message file does not exist: $message_file" >&2
        exit 2
    fi

    if has_valid_signoff <"$message_file"; then
        return
    fi

    cat >&2 <<'EOF'
DCO check: commit message is missing a valid Signed-off-by trailer.

Create signed-off commits with:
    git commit --signoff

Fix the current commit with:
    git commit --amend --signoff
EOF
    exit 1
}

check_history() {
    revision=$1
    missing=0
    checked=0

    # GitHub creates merge commits without a contributor-authored message.
    # Their introduced non-merge commits are still traversed and checked.
    for commit in $(git rev-list --reverse --no-merges "$revision"); do
        checked=$((checked + 1))
        if git log -1 --format=%B "$commit" | has_valid_signoff; then
            continue
        fi

        echo "DCO check: commit $commit is missing a valid Signed-off-by trailer" >&2
        git log -1 --format='  %h %s (%an <%ae>)' "$commit" >&2
        missing=$((missing + 1))
    done

    if [ "$missing" -ne 0 ]; then
        echo "DCO check: $missing of $checked commits failed" >&2
        exit 1
    fi

    echo "DCO check: all $checked non-merge commits carry a valid Signed-off-by trailer"
}

[ "$#" -eq 2 ] || usage

case $1 in
    --message-file)
        check_message_file "$2"
        ;;
    --history)
        check_history "$2"
        ;;
    *)
        usage
        ;;
esac
