"""Connect stdio to a forked bench server (server.py --daemon). Standard library only, so it
starts in milliseconds.

    python -m custody_bench.attach DAEMON_SOCKET CONTROL_SOCKET
"""

import json
import socket
import sys
import threading


def main() -> None:
    daemon_path, control_path = sys.argv[1], sys.argv[2]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(daemon_path)
    sock.sendall(json.dumps({"control": control_path}).encode() + b"\n")

    def upstream() -> None:
        stdin = sys.stdin.buffer.raw
        while chunk := stdin.read(65536):
            sock.sendall(chunk)
        sock.shutdown(socket.SHUT_WR)

    threading.Thread(target=upstream, daemon=True).start()
    stdout = sys.stdout.buffer
    while chunk := sock.recv(65536):
        stdout.write(chunk)
        stdout.flush()


if __name__ == "__main__":
    main()
