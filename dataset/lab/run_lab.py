#!/usr/bin/env python3
"""Handshake dataset lab.

Starts a local TLS server, then runs a set of real TLS clients against it one
at a time while tcpdump records loopback traffic. Each client gets its own
pcap, so the ground-truth label of every handshake in a file is the file name.
Standard library only; the clients are whatever is installed on the host, and
their exact versions are written to manifest.json.

    python3 dataset/lab/run_lab.py --out dataset/v0.1 --repeat 20

Needs: tcpdump (root or cap_net_raw), openssl, and any of curl, wget, go,
node, python requests/urllib3, chromium. Missing clients are skipped and
recorded as such.
"""
import argparse, hashlib, json, os, platform, shutil, ssl, subprocess, sys
import tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "localhost"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def make_cert(tmp):
    key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return crt, key


def start_server(crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(["http/1.1"])
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def out(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception:
        return None


def chromium_path():
    for base in (os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers"),):
        if os.path.isdir(base):
            for d in sorted(os.listdir(base)):
                p = os.path.join(base, d, "chrome-linux", "chrome")
                if d.startswith("chromium-") and os.path.exists(p):
                    return p
    return shutil.which("chromium") or shutil.which("google-chrome")


def build_clients(port, n, tmp):
    url = f"https://{HOST}:{port}/"
    clients = {}

    def loop(argv):  # run argv n times, each a fresh process and handshake
        def run():
            for _ in range(n):
                subprocess.run(argv, capture_output=True, timeout=60)
        return run

    def once(argv):  # the script itself makes n connections
        return lambda: subprocess.run(argv, capture_output=True, timeout=300)

    if shutil.which("curl"):
        clients["curl"] = (out(["curl", "--version"]), loop(["curl", "-sk", "--http1.1", url]))
        clients["curl-http2"] = (out(["curl", "--version"]), loop(["curl", "-sk", "--http2", url]))
    if shutil.which("wget"):
        clients["wget"] = (out(["wget", "--version"]), loop(["wget", "-q", "-O", "/dev/null", "--no-check-certificate", url]))
    if shutil.which("openssl"):
        def s_client():
            for _ in range(n):
                subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", HOST],
                               input=b"", capture_output=True, timeout=30)
        clients["openssl-s_client"] = (out(["openssl", "version"]), s_client)
    py = ("import sys,requests,urllib3;urllib3.disable_warnings();"
          f"[requests.get('{url}',verify=False,timeout=10) for _ in range({n})]")
    try:
        import requests, urllib3
        clients["python-requests"] = (f"requests {requests.__version__} urllib3 {urllib3.__version__} python {platform.python_version()}",
                                      once([sys.executable, "-c", py]))
    except ImportError:
        pass
    pystd = ("import ssl,urllib.request;c=ssl._create_unverified_context();"
             f"[urllib.request.urlopen('{url}',context=c).read() for _ in range({n})]")
    clients["python-urllib"] = (f"python {platform.python_version()} {ssl.OPENSSL_VERSION}", once([sys.executable, "-c", pystd]))
    if shutil.which("go"):
        gobin = os.path.join(tmp, "goclient")
        r = subprocess.run(["go", "build", "-o", gobin, os.path.join(HERE, "goclient.go")], capture_output=True)
        if r.returncode == 0:
            clients["go-net-http"] = (out(["go", "version"]), lambda: subprocess.run([gobin, url, str(n)], capture_output=True, timeout=120))
    if shutil.which("node"):
        js = ("process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';const https=require('https');"
              f"(async()=>{{for(let i=0;i<{n};i++)await new Promise(r=>https.get('{url}',{{agent:new https.Agent({{keepAlive:false}})}},x=>{{x.resume();x.on('end',r)}}).on('error',r));}})()")
        clients["node-https"] = (f"node {out(['node', '--version'])}", once(["node", "-e", js]))
    chrome = chromium_path()
    if chrome:
        def chromium():
            for _ in range(max(3, n // 4)):  # each launch is a fresh profile; several handshakes per launch
                d = tempfile.mkdtemp(dir=tmp)
                subprocess.run([chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-quic",
                                "--ignore-certificate-errors", f"--user-data-dir={d}",
                                "--virtual-time-budget=3000", "--dump-dom", url],
                               capture_output=True, timeout=60)
        clients["chromium-headless"] = (out([chrome, "--version"]), chromium)
    return clients


def capture(pcap, port, run):
    proc = subprocess.Popen(["tcpdump", "-n", "-Z", "root", "-i", "lo", "-U", "-s", "0", "-w", pcap,
                             f"tcp port {port}"], stderr=subprocess.PIPE, text=True)
    # tcpdump prints "listening on" once the capture socket is open; clients
    # started earlier than that would be missed.
    deadline = time.time() + 10
    while time.time() < deadline:
        line = proc.stderr.readline()
        if "listening on" in line or not line:
            break
    time.sleep(0.5)
    run()
    time.sleep(1.0)
    proc.terminate()
    proc.wait(timeout=10)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scrub_proxy_env():
    """Clients must talk to the loopback server directly, never through a proxy."""
    for k in list(os.environ):
        if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            del os.environ[k]
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "*"


def main():
    scrub_proxy_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--repeat", type=int, default=20)
    args = ap.parse_args()
    if not shutil.which("tcpdump"):
        sys.exit("tcpdump is required")
    os.makedirs(os.path.join(args.out, "pcap"), exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        crt, key = make_cert(tmp)
        srv, port = start_server(crt, key)
        clients = build_clients(port, args.repeat, tmp)
        entries = {}
        for label, (version, run) in clients.items():
            pcap = os.path.join(args.out, "pcap", f"{label}.pcap")
            print(f"capturing {label} ...", flush=True)
            capture(pcap, port, run)
            entries[label] = {"client_version": version, "pcap": f"pcap/{label}.pcap",
                              "sha256": sha256(pcap), "requested_connections": args.repeat}
        srv.shutdown()
    manifest = {
        "dataset_version": os.path.basename(os.path.normpath(args.out)),
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {"os": platform.platform(), "kernel": platform.release(), "machine": platform.machine(),
                        "server_tls": ssl.OPENSSL_VERSION, "target_host": HOST, "transport": "loopback",
                        "server_alpn": ["http/1.1"]},
        "labels": entries,
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"wrote {len(entries)} captures to {args.out}")


if __name__ == "__main__":
    main()
