#!/usr/bin/env bash
# git_docker_dig.sh -- Modern forensics trend: flags hidden in git history or
# Docker image layers rather than classic file carving.
#
# Requires: git, docker, tar, jq
#
# Usage:
#   ./git_docker_dig.sh git <path-to-repo>
#   ./git_docker_dig.sh docker <image-name-or-tar>

set -uo pipefail

sep() { printf '\n=== %s ===\n' "$1"; }

git_dig() {
    local repo="$1"
    cd "$repo" || { echo "no such dir: $repo"; exit 1; }

    sep "git log (all branches, full diffs)"
    git log --all -p | head -300

    sep "grep flag pattern across all commits/branches"
    git log --all -p | grep -Ei 'flag\{|ctf\{|flag:' 

    sep "dangling/unreachable commits (deleted history)"
    git fsck --full --unreachable --no-reflog 2>/dev/null

    sep "all reflogs (recovers 'deleted' commits still in local repo)"
    git reflog show --all 2>/dev/null

    sep "diff of every commit's changed files (find suspicious additions/removals)"
    git log --all --name-status --oneline | head -100

    sep "stash contents (often overlooked)"
    git stash list
    git stash show -p 2>/dev/null

    echo
    echo "[i] To inspect a specific dangling commit found above:"
    echo "    git show <hash>"
    echo "[i] To check out a deleted branch/commit into a temp branch:"
    echo "    git checkout -b recovered <hash>"
}

docker_dig() {
    local target="$1"

    if [[ -f "$target" ]]; then
        sep "treating $target as a saved image tar"
        WORKDIR=$(mktemp -d)
        tar -xf "$target" -C "$WORKDIR"
        echo "[+] Extracted to $WORKDIR"
    else
        sep "saving docker image $target to inspect layers"
        WORKDIR=$(mktemp -d)
        docker save "$target" -o "$WORKDIR/image.tar"
        tar -xf "$WORKDIR/image.tar" -C "$WORKDIR"
    fi

    sep "manifest.json (layer order)"
    cat "$WORKDIR/manifest.json" 2>/dev/null | jq . 2>/dev/null || cat "$WORKDIR/manifest.json" 2>/dev/null

    sep "extracting each layer and grepping for flags"
    for layer_tar in "$WORKDIR"/*/layer.tar; do
        [[ -e "$layer_tar" ]] || continue
        layer_dir=$(dirname "$layer_tar")
        mkdir -p "$layer_dir/rootfs"
        tar -xf "$layer_tar" -C "$layer_dir/rootfs" 2>/dev/null
        echo "--- layer: $layer_dir ---"
        grep -rIiE 'flag\{|ctf\{' "$layer_dir/rootfs" 2>/dev/null
    done

    sep "history (Dockerfile instructions, sometimes leak secrets in RUN/ENV)"
    docker history --no-trunc "$target" 2>/dev/null

    echo
    echo "[i] Layer directories left at: $WORKDIR"
    echo "    A file added in one layer and deleted in a later layer is only visible"
    echo "    by inspecting the earlier layer's rootfs directly -- the final image"
    echo "    (docker run) won't show it, since overlay filesystems hide deleted files."
}

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 git <repo-path>"
    echo "       $0 docker <image-name-or-tar-path>"
    exit 1
fi

case "$1" in
    git) git_dig "$2" ;;
    docker) docker_dig "$2" ;;
    *) echo "Unknown mode: $1 (use 'git' or 'docker')" ;;
esac
