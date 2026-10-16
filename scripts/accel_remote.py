#!/usr/bin/env python3
# NovaWAF 硬件加速任务：远程构建/部署/测试辅助（SSH，paramiko）
# 用法:
#   python accel_remote.py exec "<remote shell command>"
#   python accel_remote.py put  <local> <remote>
#   python accel_remote.py get  <remote> <local>
# 仅用于本任务的 192.168.100.2 构建机；凭据来自环境变量或下方默认值。
import os
import sys
import paramiko

HOST = os.environ.get("NOVA_HOST", "192.168.100.2")
USER = os.environ.get("NOVA_USER", "mao")
PASS = os.environ.get("NOVA_PASS", "MAO5201314sm")
PORT = int(os.environ.get("NOVA_PORT", "22"))


def client():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15,
              allow_agent=False, look_for_keys=False)
    return c


def run(cmd, timeout=600):
    c = client()
    try:
        stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout, get_pty=False)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        if out:
            sys.stdout.write(out)
        if err:
            sys.stderr.write(err)
        sys.stdout.flush()
        return rc
    finally:
        c.close()


def put(local, remote):
    c = client()
    try:
        sftp = c.open_sftp()
        sftp.put(local, remote)
        sftp.close()
        print(f"[put] {local} -> {HOST}:{remote}")
    finally:
        c.close()


def get(remote, local):
    c = client()
    try:
        sftp = c.open_sftp()
        sftp.get(remote, local)
        sftp.close()
        print(f"[get] {HOST}:{remote} -> {local}")
    finally:
        c.close()


def putin(local, remote):
    """经 exec stdin 写文件（规避部分主机 sftp put 被截断的问题）"""
    with open(local, "rb") as f:
        data = f.read()
    c = client()
    try:
        stdin, stdout, stderr = c.exec_command(f"cat > '{remote}' && wc -c < '{remote}'")
        stdin.write(data)
        stdin.flush()
        stdin.channel.shutdown_write()
        n = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        print(f"[putin] {local} -> {HOST}:{remote} bytes={n}")
        if err:
            sys.stderr.write(err + "\n")
        if n != str(len(data)):
            raise SystemExit(f"size mismatch local={len(data)} remote={n}")
    finally:
        c.close()


def run_stdin(local, cmd, timeout=600):
    """以 local 文件内容作为远端 cmd 的标准输入运行（如 python3 - args...），远端无需落盘"""
    with open(local, "rb") as f:
        data = f.read()
    c = client()
    try:
        stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
        stdin.write(data)
        stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        if out:
            sys.stdout.write(out)
        if err:
            sys.stderr.write(err)
        return rc
    finally:
        c.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    action = sys.argv[1]
    if action == "exec":
        sys.exit(run(sys.argv[2], timeout=int(sys.argv[3]) if len(sys.argv) > 3 else 600))
    if action == "put":
        put(sys.argv[2], sys.argv[3])
    elif action == "putin":
        putin(sys.argv[2], sys.argv[3])
    elif action == "get":
        get(sys.argv[2], sys.argv[3])
    elif action == "stdin":
        # stdin <local_file> <remote command...>
        rc = run_stdin(sys.argv[2], " ".join(sys.argv[3:]), timeout=int(sys.argv[-1]) if False else 600)
        sys.exit(rc)
    else:
        print(__doc__)
        sys.exit(2)
