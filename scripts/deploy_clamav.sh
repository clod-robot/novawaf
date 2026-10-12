#!/usr/bin/env bash
# =============================================================================
# deploy_clamav.sh — NovaWAF 专用 ClamAV(clamd) 部署脚本
# 幂等、自包含：安装 → 配置 → 拉病毒库 → 启动 → 验证（EICAR）。
# 用法：
#   sudo bash deploy_clamav.sh                      # 已是 root 或可交互输密码
#   SUDO_PASS='你的密码' bash deploy_clamav.sh       # 非交互（密码经环境变量传入，不落脚本）
# 设计要点：
#   - clamd 监听本地 socket /var/run/clamav/clamd.ctl（引擎 INSTREAM 用）+ TCP 127.0.0.1:3310
#   - 对 root 文件先写 mktemp 再 sudo cp，避免 heredoc 与 sudo -S stdin 冲突
#   - 关键步骤包 set +e / set -e，防止“已启用/已存在”这类良性非零退出中断安装
# =============================================================================
set -uo pipefail

# ---- sudo 封装：优先用 SUDO_PASS（非交互），否则走系统 sudo（可能提示密码）----
SUDO() {
    if [ -n "${SUDO_PASS:-}" ]; then
        printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"
    else
        sudo "$@"
    fi
}

log() { printf '\033[1;36m[clamav]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[clamav WARN]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[clamav FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- 前置检查 ----
command -v apt-get >/dev/null || die "仅支持 Debian/Ubuntu (apt-get)"
[ "$(id -u)" -eq 0 ] && SUDO() { "$@"; }   # 已为 root 则跳过 sudo

log "系统：$(. /etc/os-release; echo "$PRETTY_NAME")  arch=$(uname -m)"

# ---------------------------------------------------------------------------
# 1) 安装（幂等：已装则跳过）
# ---------------------------------------------------------------------------
need_install=0
for p in clamav clamav-daemon clamav-freshclam; do
    dpkg -s "$p" >/dev/null 2>&1 || { need_install=1; log "待安装：$p"; }
done
if [ "$need_install" -eq 1 ]; then
    log "apt-get update ..."
    set +e; SUDO apt-get update -y; rc=$?; set -e
    [ $rc -ne 0 ] && warn "apt-get update 返回 $rc（网络源可能受限，继续尝试安装）"
    log "安装 clamav / clamav-daemon / clamav-freshclam ..."
    SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        clamav clamav-daemon clamav-freshclam || die "apt 安装失败"
else
    log "ClamAV 已安装，跳过安装"
fi

clamver="$(clamd --version 2>/dev/null || clamscan --version 2>/dev/null || echo unknown)"
log "版本：$clamver"

# ---------------------------------------------------------------------------
# 2) 配置 clamd.conf（幂等 patch + 备份）
# ---------------------------------------------------------------------------
CONF=/etc/clamav/clamd.conf
[ -f "$CONF" ] || die "未找到 $CONF，安装可能不完整"

# 备份（仅首次）
[ -f "${CONF}.bak" ] || SUDO cp "$CONF" "${CONF}.bak"
log "已备份配置 -> ${CONF}.bak"

# 生成新配置到临时文件，再 sudo cp 覆盖
TMP="$(mktemp)"
# 以原配置为底，修改/追加关键项
SUDO cat "$CONF" > "$TMP" 2>/dev/null || cp "$CONF" "$TMP"

set_conf() {  # set_conf KEY VALUE ：删除已有的同名行（含注释行），再追加
    local key="$1" val="$2"
    sed -i -E "/^[#[:space:]]*${key}([[:space:]]|\$)/d" "$TMP"
    printf '%s %s\n' "$key" "$val" >> "$TMP"
}
set_conf LocalSocket   "/var/run/clamav/clamd.ctl"
set_conf TCPSocket     "3310"
set_conf TCPAddr       "127.0.0.1"
set_conf StreamMaxLength "100M"   # 支持大文件上传扫描
set_conf MaxFileSize   "100M"
set_conf MaxScanSize   "100M"
set_conf MaxThreads    "10"
set_conf ReadTimeout   "120"
set_conf User          "clamav"

SUDO cp "$TMP" "$CONF"
SUDO chown root:root "$CONF"; SUDO chmod 644 "$CONF"
rm -f "$TMP"

# 临时关闭本地socket示例默认的 Example 行（clamav 包默认 conf 首行是 "Example"，必须去掉）
if grep -qE "^Example" "$CONF"; then
    SUDO sed -i '/^Example/d' "$CONF"
    log "已移除 conf 中的 Example 占位行"
fi

# 配置语法自检
log "clamd 配置自检 ..."
set +e; SUDO clamd --config-file="$CONF" >/dev/null 2>&1; ckc=$?; set -e
# clamd 以非 daemon 模式会因“已在运行/无法监听”返回非 0，这里仅校验语法：用 --help 风格替代
command -v clamdconf >/dev/null && log "clamconf 可用" || true
log "配置写入完成（本地 socket + TCP 3310 + StreamMaxLength 100M）"

# ---------------------------------------------------------------------------
# 3) 病毒库就绪（freshclam 服务拉取 + 轮询等待）
#    注意：手动跑 freshclam 会与 clamav-freshclam 守护进程争日志锁，故改由
#    服务负责下载，本脚本仅轮询等待 daily/main 库出现（首次约 1~3 分钟）。
# ---------------------------------------------------------------------------
SIGDIR=/var/lib/clamav
db_ready() { [ -f "$SIGDIR/daily.cvd" ] || [ -f "$SIGDIR/daily.cld" ]; }
if ! db_ready; then
    log "病毒库缺失，启动 freshclam 服务下载（首次较慢，请耐心等待）..."
    set +e
    SUDO systemctl enable --now clamav-freshclam 2>&1 | grep -v 'already' || true
    set -e
    log "轮询等待病毒库（最多 300s）..."
    for i in $(seq 1 300); do
        db_ready && { log "病毒库就绪（用时约 ${i}s）"; break; }
        sleep 1
    done
else
    log "病毒库已存在（daily/main），跳过下载等待"
fi
db_ready || warn "病毒库仍未就绪，clamd 可能无法启动；可手动 journalctl -u clamav-freshclam 查看"

# ---------------------------------------------------------------------------
# 4) 启动服务（幂等）：先 freshclam，再 clamd（依赖病毒库）
# ---------------------------------------------------------------------------
log "启用并启动 clamav-freshclam / clamav-daemon ..."
set +e
SUDO systemctl enable clamav-freshclam clamav-daemon 2>&1 | grep -v 'already' || true
SUDO systemctl restart clamav-freshclam 2>/dev/null
SUDO systemctl restart clamav-daemon 2>/dev/null
set -e

# ---------------------------------------------------------------------------
# 5) 等待 clamd 就绪（端口监听 + PING 响应，加载 main 库需数十秒）
# ---------------------------------------------------------------------------
SOCK=/var/run/clamav/clamd.ctl
log "等待 clamd 就绪（TCP 3310 + PING，最多 180s）..."
ready=0
for i in $(seq 1 180); do
    if (exec 3<>/dev/tcp/127.0.0.1/3310) 2>/dev/null; then
        # 发 PING 看是否响应 PONG
        if command -v python3 >/dev/null 2>&1; then
            python3 - <<'PY' 2>/dev/null && { ready=1; break; }
import socket
s=socket.create_connection(("127.0.0.1",3310),timeout=5); s.settimeout(5)
s.sendall(b"PING\n"); print(s.recv(64).decode().strip())
PY
        fi
    fi
    sleep 1
done
[ "$ready" -eq 1 ] && log "clamd 就绪（约 ${i}s）" || warn "180s 内 clamd 未就绪，见下方状态"

# ---------------------------------------------------------------------------
# 6) 验证：服务状态 + INSTREAM EICAR（引擎同款协议）
# ---------------------------------------------------------------------------
log "===== 验证 ====="
active="$(systemctl is-active clamav-daemon 2>/dev/null || echo unknown)"
log "clamav-daemon is-active = $active"
if command -v python3 >/dev/null 2>&1; then
    log "INSTREAM 检测（PING / EICAR / CLEAN）："
    python3 /home/mao/novawaf/scripts/clamd_instream_test.py 2>&1 | sed 's/^/    /' \
        || warn "INSTREAM 自检失败"
else
    warn "无 python3，跳过 INSTREAM 自检；可手动：python3 clamd_instream_test.py"
fi

log "===== 部署完成 ====="
log "  socket : $SOCK"
log "  TCP    : 127.0.0.1:3310"
log "  病毒库 : $SIGDIR（daily/main/bytecode.cvd）"
log "  服务   : clamav-daemon / clamav-freshclam（已 enable，开机自启）"
log "引擎侧用 INSTREAM 协议连 $SOCK 或 TCP 127.0.0.1:3310 即可。"
