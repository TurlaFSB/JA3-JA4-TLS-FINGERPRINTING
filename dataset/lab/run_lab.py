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

# Browser ClientHello profiles shipped with curl_cffi (curl-impersonate). Real
# browsers are not installable in the lab, so these stand in for them and are
# labeled as impersonation, never as the browser itself.
IMPERSONATE = ["chrome150", "chrome142", "chrome131", "chrome124", "chrome120", "edge101",
               "firefox147", "firefox133", "safari2601", "safari180_ios", "tor145"]


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


def real_chromium_clients(chromium_dir, url, n, tmp):
    """label -> (version, run) for real Chromium builds fetched by fetch_chromium.sh.

    The headless-shell builds from 116 on do not return from --dump-dom, so each
    launch loads the page for a few seconds and is then killed; the capture only
    needs the connection the browser opens.
    """
    clients = {}
    if not chromium_dir or not os.path.isdir(chromium_dir):
        return clients
    for entry in sorted(os.listdir(chromium_dir)):
        folder = os.path.join(chromium_dir, entry)
        binary = os.path.join(folder, "chromium")
        if not (entry.startswith("chromium-") and os.access(binary, os.X_OK)):
            continue
        version = entry.removeprefix("chromium-")

        def run(binary=binary, folder=folder):
            env = dict(os.environ, LD_LIBRARY_PATH=folder)
            for _ in range(max(3, n // 4)):
                profile = tempfile.mkdtemp(dir=tmp)
                proc = subprocess.Popen(
                    [binary, "--headless", "--no-sandbox", "--disable-gpu", "--disable-quic",
                     "--ignore-certificate-errors", f"--user-data-dir={profile}", url],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
                time.sleep(5)
                try:
                    os.killpg(proc.pid, 9)
                except ProcessLookupError:
                    pass
        clients[f"chromium-real-{version}"] = (f"Chromium headless-shell {version} (npm @sparticuz/chromium)", run)
    return clients


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
        clients["wget-tls12"] = (out(["wget", "--version"]), loop(["wget", "-q", "-O", "/dev/null", "--no-check-certificate", "--secure-protocol=TLSv1_2", url]))
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
            clients["go-http2"] = (out(["go", "version"]) + " (HTTP/2)", lambda: subprocess.run([gobin, url, str(n), "h2"], capture_output=True, timeout=120))
    if shutil.which("node"):
        js = ("process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';const https=require('https');"
              f"(async()=>{{for(let i=0;i<{n};i++)await new Promise(r=>https.get('{url}',{{agent:new https.Agent({{keepAlive:false}})}},x=>{{x.resume();x.on('end',r)}}).on('error',r));}})()")
        clients["node-https"] = (f"node {out(['node', '--version'])}", once(["node", "-e", js]))
    py = sys.executable

    def pycode(code):
        return once([py, "-c", code])

    def have(*mods):
        return subprocess.run([py, "-c", "import " + ",".join(mods)], capture_output=True).returncode == 0

    pyv = f"python {platform.python_version()}"
    if have("httpx"):
        import httpx
        clients["python-httpx"] = (f"httpx {httpx.__version__} {pyv} {ssl.OPENSSL_VERSION}", pycode(
            f"import httpx;[httpx.Client(verify=False).get('{url}') for _ in range({n})]"))
    if have("aiohttp"):
        import aiohttp
        clients["python-aiohttp"] = (f"aiohttp {aiohttp.__version__} {pyv} {ssl.OPENSSL_VERSION}", pycode(
            "import asyncio,aiohttp\n"
            "async def main():\n"
            f"    for _ in range({n}):\n"
            "        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as s:\n"
            f"            async with s.get('{url}') as r:\n"
            "                await r.read()\n"
            "asyncio.run(main())\n"))
    if shutil.which("curl"):
        clients["curl-tls13"] = (out(["curl", "--version"]), loop(["curl", "-sk", "--http1.1", "--tlsv1.3", url]))
        clients["curl-tls12"] = (out(["curl", "--version"]), loop(["curl", "-sk", "--http1.1", "--tlsv1.2", "--tls-max", "1.2", url]))
    if shutil.which("openssl"):
        def s_client_h2():
            for _ in range(n):
                subprocess.run(["openssl", "s_client", "-alpn", "h2", "-connect", f"127.0.0.1:{port}", "-servername", HOST],
                               input=b"", capture_output=True, timeout=30)
        clients["openssl-s_client-alpn-h2"] = (out(["openssl", "version"]), s_client_h2)

        def s_client12():
            for _ in range(n):
                subprocess.run(["openssl", "s_client", "-tls1_2", "-connect", f"127.0.0.1:{port}", "-servername", HOST],
                               input=b"", capture_output=True, timeout=30)
        clients["openssl-s_client-tls12"] = (out(["openssl", "version"]), s_client12)
    if shutil.which("java"):
        java_src = os.path.join(HERE, "JavaClient.java")
        jv = subprocess.run(["java", "-version"], capture_output=True, text=True).stderr.splitlines()
        jv = next((l for l in jv if "version" in l and "Picked up" not in l), "java")
        clients["java-httpclient"] = (jv, once(["java", java_src, url, str(n)]))
        clients["java-urlconnection"] = (jv, once(["java", java_src, url, str(n), "urlconn"]))
    if shutil.which("ruby"):
        rb = ("require 'net/http';require 'openssl';u=URI(ARGV[0]);"
              "ARGV[1].to_i.times{Net::HTTP.start(u.host,u.port,use_ssl:true,verify_mode:OpenSSL::SSL::VERIFY_NONE){|h|h.get('/')}}")
        clients["ruby-net-http"] = (out(["ruby", "-v"]), once(["ruby", "-e", rb, url, str(n)]))
    if shutil.which("php"):
        ph = (f"$c=stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]]);"
              f"for($i=0;$i<{n};$i++){{@file_get_contents('{url}',false,$c);}}")
        clients["php-stream"] = (out(["php", "-v"]), once(["php", "-r", ph]))
        if subprocess.run(["php", "-r", "exit(extension_loaded('curl') ? 0 : 1);"]).returncode == 0:
            pc = (f"for($i=0;$i<{n};$i++){{$h=curl_init('{url}');curl_setopt($h,CURLOPT_SSL_VERIFYPEER,false);"
                  f"curl_setopt($h,CURLOPT_SSL_VERIFYHOST,0);curl_setopt($h,CURLOPT_RETURNTRANSFER,true);"
                  f"curl_exec($h);curl_close($h);}}")
            clients["php-curl"] = (out(["php", "-v"]) + "; " + out(["php", "-r", "echo curl_version()['version'].' '.curl_version()['ssl_version'];"]), once(["php", "-r", pc]))
    if have("curl_cffi"):
        import curl_cffi
        for imp in IMPERSONATE:
            code = (f"from curl_cffi import requests as r\n"
                    f"for _ in range({n}):\n"
                    f"    r.get('{url}', impersonate='{imp}', verify=False, timeout=10)\n")
            clients[f"curl_cffi-{imp}"] = (f"curl_cffi {curl_cffi.__version__} impersonate={imp}; {curl_cffi.__curl_version__}", pycode(code))
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


def capture(pcap, ports, run):
    ports = [ports] if isinstance(ports, int) else list(ports)
    bpf = " or ".join(f"tcp port {p}" for p in ports)
    proc = subprocess.Popen(["tcpdump", "-n", "-Z", "root", "-i", "lo", "-U", "-s", "0", "-w", pcap,
                             bpf], stderr=subprocess.PIPE, text=True)
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
        if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "java_tool_options"):
            del os.environ[k]
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "*"


def main():
    scrub_proxy_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--repeat", type=int, default=20)
    ap.add_argument("--extra-impersonate", default="", help="comma-separated extra curl_cffi profiles to capture")
    ap.add_argument("--chromium-dir", help="directory of chromium-<version>/chromium builds (see fetch_chromium.sh)")
    ap.add_argument("--only", help="comma-separated client labels to run (default: all available)")
    args = ap.parse_args()
    IMPERSONATE.extend(p for p in args.extra_impersonate.split(",") if p and p not in IMPERSONATE)
    if not shutil.which("tcpdump"):
        sys.exit("tcpdump is required")
    os.makedirs(os.path.join(args.out, "pcap"), exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        crt, key = make_cert(tmp)
        srv, port = start_server(crt, key)
        clients = build_clients(port, args.repeat, tmp)
        clients.update(real_chromium_clients(args.chromium_dir, f"https://{HOST}:{port}/", args.repeat, tmp))
        if args.only:
            wanted = set(args.only.split(","))
            clients = {k: v for k, v in clients.items() if k in wanted}
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
