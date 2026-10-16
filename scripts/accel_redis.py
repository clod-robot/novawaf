#!/usr/bin/env python3
# 极简 Redis 命令行（纯标准库 RESP），在被测服务器本地执行。
# 用法: python3 accel_redis.py GET key | SET key value | INCR key | DEL key [..] | HGET key field
import socket
import sys

HOST, PORT = "127.0.0.1", 6379


def send(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        a = a.encode() if isinstance(a, str) else a
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def read_sock(f):
    line = f.readline().rstrip(b"\r\n")
    t = line[:1]
    if t == b"+":
        return line[1:].decode()
    if t == b"-":
        return "ERR " + line[1:].decode()
    if t == b":":
        return int(line[1:])
    if t == b"$":
        n = int(line[1:])
        if n < 0:
            return None
        data = f.read(n)
        f.read(2)
        return data.decode("utf-8", "replace")
    if t == b"*":
        n = int(line[1:])
        return [read_sock(f) for _ in range(n)] if n >= 0 else None
    return line.decode()


def main():
    s = socket.create_connection((HOST, PORT), timeout=5)
    f = s.makefile("rb")
    args = list(sys.argv[1:])
    args[0] = args[0].upper()
    # SETFILE key file -> 从文件读取 value，规避 shell 引号问题
    if args[0] == "SETFILE":
        with open(args[2], "rb") as fh:
            args = ["SET", args[1], fh.read()]
    cmd = [a.upper() if i == 0 else a for i, a in enumerate(args)]
    s.sendall(send(*cmd))
    res = read_sock(f)
    if isinstance(res, (dict, list)):
        for x in res:
            print(x)
    elif res is None:
        print("(nil)")
    else:
        print(res)
    s.close()


if __name__ == "__main__":
    main()
