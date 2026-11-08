#!/usr/bin/env bash
# NovaWAF 引擎版本化运维（零停机升级 / 回退 / 滚动重启）
#
# 目录布局（状态唯一真值源，管理端经 sudo 以固定 argv 调用，无 shell 拼接）：
#   $ROOT/versions/<ver>/novawaf-engine   各版本二进制 + meta.json
#   $ROOT/current  -> versions/<ver>/novawaf-engine   当前版本（systemd ExecStart 指向它）
#   $ROOT/previous -> versions/<ver>/novawaf-engine   上一版本（回退目标；备份只留最近一版）
#
# 零停机原理：引擎 --supervise master 收到 SIGUSR2 后先拉起新 worker（SO_REUSEPORT
# 与旧 worker 重叠监听），READY 后再 SIGQUIT 旧 worker 排空，全程无丢包。
#
# 输出契约：stdout 单行 JSON；失败输出 {"ok":false,"error":"..."} 且退出码非 0。
set -u
export LC_ALL=C

ROOT="${NOVA_ENGINE_ROOT:-/opt/novawaf/engine}"
RUN_DIR="${NOVA_RUN_DIR:-/opt/novawaf/run}"
PIDFILE="$RUN_DIR/engine-master.pid"
LOCK="$ROOT/.ops.lock"
BIN_NAME="novawaf-engine"
UNIT="novawaf-engine"
SETTLE_TIMEOUT=55   # 滚动排空 30s 兜底 + 启动余量

jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
die()  { printf '{"ok":false,"error":"%s"}\n' "$(jesc "$1")"; exit 1; }

[ -d "$ROOT" ] || die "引擎根目录不存在: $ROOT"
mkdir -p "$ROOT/versions"

ver_from_link() {  # $1=链接名 → 版本号（无则空）
    local t
    t=$(readlink -f "$ROOT/$1" 2>/dev/null) || { printf ''; return; }
    case "$t" in
        "$ROOT"/versions/*/"$BIN_NAME") basename "$(dirname "$t")" ;;
        *) printf '' ;;
    esac
}

ver_of_pid() {  # $1=pid → 运行中版本号
    local t
    t=$(readlink -f "/proc/$1/exe" 2>/dev/null) || { printf ''; return; }
    case "$t" in
        "$ROOT"/versions/*/"$BIN_NAME") basename "$(dirname "$t")" ;;
        *) printf '' ;;
    esac
}

master_pid() {  # → master pid（存活 supervise master），失败返回 1
    [ -f "$PIDFILE" ] || return 1
    local p exe
    p=$(head -c 16 "$PIDFILE" | tr -dc '0-9')
    [ -n "$p" ] && [ -d "/proc/$p" ] || return 1
    # 不能用 readlink -f：master 可能仍持有被 gc 清理的旧版本 inode（二进制已删），
    # 此时 readlink -f 返回空导致误判 master 不在。改用 readlink 并剥除 " (deleted)"。
    exe=$(readlink "/proc/$p/exe" 2>/dev/null) || return 1
    exe="${exe% (deleted)}"
    case "$exe" in "$ROOT"/versions/*) ;; *) return 1 ;; esac
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- '--supervise' || return 1
    printf '%s' "$p"
}

# 等待滚动稳定：master 存活且仅剩 1 个 worker 且版本匹配 expect
wait_settled() {  # $1=期望版本 $2=超时秒
    local end=$(( $(date +%s) + $2 )) mp cnt v
    while :; do
        if mp=$(master_pid); then
            cnt=$(pgrep -P "$mp" | wc -l)
            if [ "$cnt" -eq 1 ]; then
                v=$(ver_of_pid "$(pgrep -P "$mp" | head -n1)")
                [ "$v" = "$1" ] && return 0
            fi
        fi
        [ "$(date +%s)" -ge "$end" ] && return 1
        sleep 1
    done
}

rolling() {  # 触发滚动重启：master 不在则走 systemd 冷启动
    local mp
    if mp=$(master_pid); then
        kill -USR2 "$mp" || die "SIGUSR2 发送失败(master=$mp)"
    else
        systemctl restart "$UNIT" 2>/dev/null || die "master 未运行且 systemd 重启失败"
    fi
}

gc_versions() {  # 备份只留最近一版：仅保留 current + previous
    local cur prev b d
    cur=$(ver_from_link current); prev=$(ver_from_link previous)
    for d in "$ROOT"/versions/*; do
        [ -d "$d" ] || continue
        b=${d##*/}
        if [ "$b" != "$cur" ] && [ "$b" != "$prev" ]; then
            rm -rf "$d"
        fi
    done
}

cmd_list() {
    local cur prev items="" b d size mt sha iscur isprev meta
    cur=$(ver_from_link current); prev=$(ver_from_link previous)
    for d in "$ROOT"/versions/*; do
        [ -d "$d" ] || continue
        b=${d##*/}
        [ -f "$d/$BIN_NAME" ] || continue
        size=$(stat -c %s "$d/$BIN_NAME" 2>/dev/null || echo 0)
        mt=$(stat -c %Y "$d/$BIN_NAME" 2>/dev/null || echo 0)
        sha=""
        meta="$d/meta.json"
        if [ -f "$meta" ]; then
            sha=$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$meta" | head -n1)
        fi
        [ -z "$sha" ] && sha=$(sha256sum "$d/$BIN_NAME" 2>/dev/null | cut -c1-64)
        iscur=false; isprev=false
        [ "$b" = "$cur" ] && iscur=true
        [ "$b" = "$prev" ] && isprev=true
        items="$items{\"version\":\"$(jesc "$b")\",\"size\":$size,\"mtime\":$mt,\"sha256\":\"$sha\",\"current\":$iscur,\"previous\":$isprev},"
    done
    printf '{"ok":true,"current":"%s","previous":"%s","versions":[%s]}\n' \
        "$(jesc "$cur")" "$(jesc "$prev")" "${items%,}"
}

cmd_status() {
    local cur prev mp wjson="" wpids w v port threads up
    cur=$(ver_from_link current); prev=$(ver_from_link previous)
    if mp=$(master_pid); then
        wpids=$(pgrep -P "$mp" || true)
        for w in $wpids; do
            v=$(ver_of_pid "$w")
            wjson="$wjson{\"pid\":$w,\"version\":\"$(jesc "$v")\"},"
        done
        port=$(tr '\0' '\n' < "/proc/$mp/cmdline" 2>/dev/null | awk '/^--supervise$/{getline; print; exit}')
        threads=$(tr '\0' '\n' < "/proc/$mp/cmdline" 2>/dev/null | awk '/^--supervise$/{getline; getline; print; exit}')
        up=$(ps -o etimes= -p "$mp" 2>/dev/null | tr -d ' ')
        printf '{"ok":true,"running":true,"supervise":true,"masterPid":%s,"port":%s,"threads":%s,"uptimeSec":%s,"current":"%s","previous":"%s","workers":[%s]}\n' \
            "$mp" "${port:-0}" "${threads:-0}" "${up:-0}" "$(jesc "$cur")" "$(jesc "$prev")" "${wjson%,}"
    else
        printf '{"ok":true,"running":false,"supervise":false,"current":"%s","previous":"%s","workers":[]}\n' \
            "$(jesc "$cur")" "$(jesc "$prev")"
    fi
}

cmd_install() {  # $1=管理端上传的临时二进制
    local tmp="$1" v dst sha size
    [ -f "$tmp" ] || die "安装包不存在: $tmp"
    chmod 755 "$tmp" 2>/dev/null || true
    v=$("$tmp" --version 2>/dev/null | head -n1 | tr -d '\r')
    [[ "$v" =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$ ]] || die "二进制 --version 输出非法（非 NovaWAF 引擎？）"
    [ "$v" = "$(ver_from_link current)" ] && die "版本 $v 正在运行，无需重复安装"
    dst="$ROOT/versions/$v"
    mkdir -p "$dst"
    mv -f "$tmp" "$dst/$BIN_NAME" || die "安装失败（目标 $dst）"
    chmod 755 "$dst/$BIN_NAME"
    # 安装后自检：必须从版本目录路径可执行且版本一致
    local chk
    chk=$("$dst/$BIN_NAME" --version 2>/dev/null | head -n1 | tr -d '\r')
    [ "$chk" = "$v" ] || { rm -rf "$dst"; die "安装后自检失败(--version=$chk)"; }
    sha=$(sha256sum "$dst/$BIN_NAME" | cut -c1-64)
    size=$(stat -c %s "$dst/$BIN_NAME")
    printf '{"sha256":"%s","version":"%s","size":%s,"installedAt":%s}\n' \
        "$sha" "$(jesc "$v")" "$size" "$(date +%s)" > "$dst/meta.json"
    printf '{"ok":true,"version":"%s","size":%s,"sha256":"%s"}\n' "$(jesc "$v")" "$size" "$sha"
}

cmd_activate() {  # $1=目标版本：切符号链接 + 滚动重启 + 失败自动回切
    local v="$1" cur oldcur
    [[ "$v" =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$ ]] || die "版本号非法"
    [ -f "$ROOT/versions/$v/$BIN_NAME" ] || die "版本未安装: $v"
    cur=$(ver_from_link current)
    [ "$v" = "$cur" ] && die "版本 $v 已是当前运行版本"
    oldcur=""
    [ -n "$cur" ] && oldcur=$(readlink -f "$ROOT/current")

    ln -sfn "$ROOT/versions/$v/$BIN_NAME" "$ROOT/current" || die "切换 current 符号链接失败"
    [ -n "$oldcur" ] && ln -sfn "$oldcur" "$ROOT/previous"

    rolling
    if wait_settled "$v" "$SETTLE_TIMEOUT"; then
        gc_versions
        printf '{"ok":true,"version":"%s","previous":"%s","rolledRestart":true}\n' "$(jesc "$v")" "$(jesc "$cur")"
    else
        # 自动回切旧版本，绝不把生产留在坏版本上
        [ -n "$oldcur" ] && ln -sfn "$oldcur" "$ROOT/current"
        rolling
        die "新版本 $v 启动校验失败，已自动回切 ${cur:-原版本}"
    fi
}

cmd_rollback() {
    local cur prev
    cur=$(ver_from_link current); prev=$(ver_from_link previous)
    [ -n "$prev" ] || die "无可回退版本（previous 为空）"
    [ -f "$ROOT/versions/$prev/$BIN_NAME" ] || die "回退目标已损坏: $prev"
    ln -sfn "$ROOT/versions/$prev/$BIN_NAME" "$ROOT/current" || die "回切符号链接失败"
    ln -sfn "$ROOT/versions/$cur/$BIN_NAME" "$ROOT/previous"
    rolling
    if wait_settled "$prev" "$SETTLE_TIMEOUT"; then
        gc_versions
        printf '{"ok":true,"version":"%s","rolledBack":true}\n' "$(jesc "$prev")"
    else
        ln -sfn "$ROOT/versions/$cur/$BIN_NAME" "$ROOT/current"
        ln -sfn "$ROOT/versions/$prev/$BIN_NAME" "$ROOT/previous"
        rolling
        die "回退到 $prev 后校验失败，已回切 $cur"
    fi
}

cmd_restart() {  # 零停机滚动重启（同版本换 worker，用于热刷新配置/内存整理）
    local cur mp oldw
    cur=$(ver_from_link current)
    [ -n "$cur" ] || die "current 符号链接未设置"
    mp=$(master_pid || true)
    oldw=""
    [ -n "$mp" ] && oldw=$(pgrep -P "$mp" | head -n1 || true)
    rolling
    if wait_settled "$cur" "$SETTLE_TIMEOUT"; then
        local nw
        nw=$(pgrep -P "$(master_pid)" | head -n1 || true)
        printf '{"ok":true,"version":"%s","oldWorker":"%s","newWorker":"%s"}\n' \
            "$(jesc "$cur")" "${oldw:-}" "${nw:-}"
    else
        die "滚动重启后未就绪（版本 $cur）"
    fi
}

CMD="${1:-}"
case "$CMD" in
    list|status) ;;
    install|activate|rollback|restart)
        exec 9>"$LOCK"
        flock -n 9 || die "另一运维操作进行中，请稍后再试"
        ;;
    *) die "用法: engine_ops.sh {list|status|install <file>|activate <ver>|rollback|restart}" ;;
esac

case "$CMD" in
    list)     cmd_list ;;
    status)   cmd_status ;;
    install)  cmd_install "${2:-}" ;;
    activate) cmd_activate "${2:-}" ;;
    rollback) cmd_rollback ;;
    restart)  cmd_restart ;;
esac
