#!/usr/bin/env python3
"""Cross-layer scenario lab: TLS fingerprint and cleartext HTTP claim together.

The mismatch rules (`ua_mismatch`, `os_mismatch`) compare what a client says in
a cleartext HTTP request (User-Agent) with what its handshake and TCP SYN
reveal. The plain handshake lab cannot exercise them because its clients speak
HTTPS only. Here each scenario is one client run against BOTH a local TLS server
and a local plain-HTTP server, from one address, with a chosen User-Agent claim,
captured into one pcap:

  * a library telling the truth (its own User-Agent)
  * a library lying (claims Chrome on Windows, or Safari on macOS)
  * a curl-impersonate profile (claims a browser, is a tool)
  * a real Chromium build (claims what it is)

Ground truth is in the manifest: `client_class` is `library`, `impersonation` or
`browser`; the host is Linux, so a Windows claim is an OS lie.

    python3 dataset/lab/run_scenarios.py --out dataset/v0.4 --repeat 10 \
        [--chromium-dir /path/with/chromium-<version>/chromium ...]

Like run_lab.py this needs tcpdump and whichever clients are installed; run it
with the interpreter of an environment that has requests, httpx and curl_cffi.
"""
import argparse, json, os, platform, shutil, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_lab as lab  # noqa: E402

UA_CHROME_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                 "Chrome/131.0.0.0 Safari/537.36")
UA_SAFARI_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                 "Version/17.0 Safari/605.1.15")

CLAIMS = {"native": None, "chrome-win": UA_CHROME_WIN, "safari-mac": UA_SAFARI_MAC}

# Browser ClientHello profiles run as impersonation scenarios (native User-Agent).
IMPERSONATE = ["chrome99", "chrome107", "chrome110", "chrome116", "chrome120", "chrome124", "chrome131",
               "chrome133a", "chrome136", "chrome142", "chrome145", "chrome146", "chrome150",
               "edge101", "firefox147", "safari2601", "tor145"]

# Browsers treat http://localhost as a secure context and change what they send
# (for example Client Hints), so the lab serves under a non-secure alias that
# resolves to loopback via /etc/hosts.
DEFAULT_HOST = "lab.test"


class PlainHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_plain_server():
    srv = HTTPServer(("127.0.0.1", 0), PlainHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def library_runners(py, https_url, http_url, n, tmp, claim):
    """label -> (client_version, run) for libraries, with an optional UA claim."""
    ua = CLAIMS[claim]
    runners = {}

    def each_url(make):
        def run():
            for url in (https_url, http_url):
                for _ in range(n):
                    make(url)
        return run

    def sp(argv, env=None):
        subprocess.run(argv, capture_output=True, timeout=60, env=env)

    if shutil.which("curl"):
        base = ["curl", "-sk", "--http1.1"] + (["-A", ua] if ua else [])
        runners["curl"] = (lab.out(["curl", "--version"]), each_url(lambda u, base=base: sp(base + [u])))
    if shutil.which("wget"):
        base = ["wget", "-q", "-O", "/dev/null", "--no-check-certificate"] + (["--user-agent", ua] if ua else [])
        runners["wget"] = (lab.out(["wget", "--version"]), each_url(lambda u, base=base: sp(base + [u])))

    def pyrun(code_for):
        def run():
            for url in (https_url, http_url):
                sp([py, "-c", code_for(url)])
        return run

    hdr = f"headers={{'User-Agent': {ua!r}}}" if ua else "headers={}"
    runners["python-requests"] = (f"python {platform.python_version()}", pyrun(lambda u: (
        f"import requests,urllib3;urllib3.disable_warnings();"
        f"[requests.get('{u}',verify=False,timeout=10,{hdr}) for _ in range({n})]")))
    if lab_has(py, "httpx"):
        runners["python-httpx"] = (f"python {platform.python_version()}", pyrun(lambda u: (
            f"import httpx;[httpx.Client(verify=False,{hdr}).get('{u}') for _ in range({n})]")))
    if shutil.which("node"):
        js = lambda u: ("process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';"
                        "const m=require(process.argv[1].startsWith('https')?'https':'http');"
                        "const h=process.env.LAB_UA?{'User-Agent':process.env.LAB_UA}:{};"
                        f"(async()=>{{for(let i=0;i<{n};i++)await new Promise(r=>m.get(process.argv[1],"
                        "{headers:h,agent:new m.Agent({keepAlive:false})},x=>{x.resume();x.on('end',r)}).on('error',r));})()")
        env = dict(os.environ, **({"LAB_UA": ua} if ua else {}))
        runners["node-https"] = (f"node {lab.out(['node', '--version'])}", lambda env=env: [
            sp(["node", "-e", js(u), u], env=env) for u in (https_url, http_url)])
    if shutil.which("go"):
        gobin = os.path.join(tmp, "goclient")
        if os.path.exists(gobin) or subprocess.run(["go", "build", "-o", gobin, os.path.join(HERE, "goclient.go")],
                                                   capture_output=True).returncode == 0:
            env = dict(os.environ, **({"LAB_UA": ua} if ua else {}))
            runners["go-net-http"] = (lab.out(["go", "version"]), lambda env=env: [
                sp([gobin, u, str(n)], env=env) for u in (https_url, http_url)])
    if shutil.which("ruby"):
        rb = ("require 'net/http';require 'openssl';u=URI(ARGV[0]);ua=ENV['LAB_UA'];"
              "ARGV[1].to_i.times{Net::HTTP.start(u.host,u.port,use_ssl:u.scheme=='https',verify_mode:OpenSSL::SSL::VERIFY_NONE){|h|"
              "r=Net::HTTP::Get.new(u);r['User-Agent']=ua if ua;h.request(r)}}")
        env = dict(os.environ, **({"LAB_UA": ua} if ua else {}))
        runners["ruby-net-http"] = (lab.out(["ruby", "-v"]), lambda env=env: [
            sp(["ruby", "-e", rb, u, str(n)], env=env) for u in (https_url, http_url)])
    if shutil.which("php"):
        env = dict(os.environ, **({"LAB_UA": ua} if ua else {}))
        ph = lambda u: (f"for($i=0;$i<{n};$i++){{$h=curl_init('{u}');curl_setopt($h,CURLOPT_SSL_VERIFYPEER,false);"
                        "curl_setopt($h,CURLOPT_SSL_VERIFYHOST,0);curl_setopt($h,CURLOPT_RETURNTRANSFER,true);"
                        "if(getenv('LAB_UA'))curl_setopt($h,CURLOPT_USERAGENT,getenv('LAB_UA'));curl_exec($h);curl_close($h);}")
        runners["php-curl"] = (lab.out(["php", "-v"]), lambda env=env: [
            sp(["php", "-r", ph(u)], env=env) for u in (https_url, http_url)])
    return runners


def lab_has(py, module):
    return subprocess.run([py, "-c", f"import {module}"], capture_output=True).returncode == 0


def chromium_runner(binary, folder, https_url, http_url, n, tmp):
    """Launch, wait for the page to load, kill. The headless-shell builds from 116
    on never return from --dump-dom, and the capture only needs the connection."""
    def run():
        env = dict(os.environ, LD_LIBRARY_PATH=folder)
        for url in (https_url, http_url):
            for _ in range(n):
                profile = tempfile.mkdtemp(dir=tmp)
                proc = subprocess.Popen(
                    [binary, "--headless", "--no-sandbox", "--disable-gpu", "--disable-quic",
                     "--ignore-certificate-errors", f"--user-data-dir={profile}", url],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
                time.sleep(4)
                try:
                    os.killpg(proc.pid, 9)
                except ProcessLookupError:
                    pass
    return run


def ensure_host_alias(host):
    """Make `host` resolve to loopback, adding an /etc/hosts line when needed."""
    import socket
    try:
        if socket.gethostbyname(host) == "127.0.0.1":
            return
    except OSError:
        pass
    with open("/etc/hosts", "a") as f:
        f.write(f"127.0.0.1 {host}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--repeat", type=int, default=10)
    ap.add_argument("--chromium-dir", help="directory of chromium-<version>/chromium builds (see fetch_chromium.sh)")
    ap.add_argument("--only", help="comma-separated scenario labels to run (default: all available)")
    ap.add_argument("--append", action="store_true", help="add the selected scenarios to an existing dataset directory")
    ap.add_argument("--host", default=DEFAULT_HOST, help="hostname the clients connect to (added to /etc/hosts if it does not resolve)")
    args = ap.parse_args()
    lab.scrub_proxy_env()
    if not shutil.which("tcpdump"):
        sys.exit("tcpdump is required")
    os.makedirs(os.path.join(args.out, "pcap"), exist_ok=True)
    py = sys.executable

    with tempfile.TemporaryDirectory() as tmp:
        crt, key = lab.make_cert(tmp)
        tls_srv, tls_port = lab.start_server(crt, key)
        http_srv, http_port = start_plain_server()
        ensure_host_alias(args.host)
        https_url, http_url = f"https://{args.host}:{tls_port}/", f"http://{args.host}:{http_port}/"

        scenarios = {}  # label -> (client_class, client, claim, version, run)
        for claim in CLAIMS:
            for client, (version, run) in library_runners(py, https_url, http_url, args.repeat, tmp, claim).items():
                scenarios[f"{client}__{claim}"] = ("library", client, claim, version, run)

        if lab_has(py, "curl_cffi"):
            import curl_cffi
            for imp in IMPERSONATE:
                def run(imp=imp):
                    for url in (https_url, http_url):
                        code = (f"from curl_cffi import requests as r\nfor _ in range({args.repeat}):\n"
                                f"    r.get('{url}', impersonate='{imp}', verify=False, timeout=10)\n")
                        subprocess.run([py, "-c", code], capture_output=True, timeout=120)
                scenarios[f"curl_cffi-{imp}__native"] = (
                    "impersonation", f"curl_cffi-{imp}", "native",
                    f"curl_cffi {curl_cffi.__version__} impersonate={imp}", run)

        if lab_has(py, "curl_cffi"):
            # An adaptive attacker: same ClientHello, but the telltale defaults are
            # removed (no Client Hints, no Sec-Fetch, HTTP/1.1 only) and the
            # headers a browser sends to a cleartext origin are written by hand.
            def run_evasive(ua=UA_CHROME_WIN):
                for url in (https_url, http_url):
                    code = ("from curl_cffi import requests as r\n"
                            "h={'User-Agent':'%s','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',"
                            "'Accept-Language':'en-US,en;q=0.9','Accept-Encoding':'gzip, deflate'}\n"
                            "for _ in range(%d):\n"
                            "    r.get('%s', impersonate='chrome142', verify=False, timeout=10, default_headers=False, headers=h, http_version='v1')\n"
                            % (ua, args.repeat, url))
                    subprocess.run([py, "-c", code], capture_output=True, timeout=120)
            scenarios["curl_cffi-chrome142__evasive"] = (
                "evasive-impersonation", "curl_cffi-chrome142-evasive", "chrome-win",
                "curl_cffi impersonate=chrome142 with default headers stripped, HTTP/1.1, claims Windows", run_evasive)
            scenarios["curl_cffi-chrome142__evasive-unix"] = (
                "evasive-impersonation", "curl_cffi-chrome142-evasive-unix", "safari-mac",
                "curl_cffi impersonate=chrome142 with default headers stripped, HTTP/1.1, claims macOS",
                lambda: run_evasive(UA_SAFARI_MAC))

        if args.chromium_dir and os.path.isdir(args.chromium_dir):
            for entry in sorted(os.listdir(args.chromium_dir)):
                binary = os.path.join(args.chromium_dir, entry, "chromium")
                if entry.startswith("chromium-") and os.access(binary, os.X_OK):
                    version = entry.removeprefix("chromium-")
                    scenarios[f"chromium-{version}__native"] = (
                        "browser", f"chromium-{version}", "native",
                        f"Chromium headless-shell {version} (npm @sparticuz/chromium)",
                        chromium_runner(binary, os.path.join(args.chromium_dir, entry), https_url, http_url,
                                        max(3, args.repeat // 2), tmp))

        full = lab.chromium_path()
        if full:
            def run_full(full=full):
                for url in (https_url, http_url):
                    for _ in range(max(3, args.repeat // 2)):
                        profile = tempfile.mkdtemp(dir=tmp)
                        subprocess.run([full, "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-quic",
                                        "--ignore-certificate-errors", f"--user-data-dir={profile}", "--dump-dom", url],
                                       capture_output=True, timeout=60)
            version = lab.out([full, "--version"]) or "Chromium (Playwright build)"
            scenarios["chromium-full__native"] = ("browser", "chromium-full", "native", version + " (full browser, new headless)", run_full)

        if args.only:
            wanted = set(args.only.split(","))
            scenarios = {k: v for k, v in scenarios.items() if k in wanted}

        manifest_labels = {}
        if args.append and os.path.exists(os.path.join(args.out, "manifest.json")):
            with open(os.path.join(args.out, "manifest.json")) as f:
                manifest_labels = json.load(f)["labels"]
        for label, (client_class, client, claim, version, run) in sorted(scenarios.items()):
            pcap = os.path.join(args.out, "pcap", f"{label}.pcap")
            print(f"capturing {label} ...", flush=True)
            lab.capture(pcap, [tls_port, http_port], run)
            manifest_labels[label] = {
                "client": client, "client_class": client_class, "ua_claim": claim,
                "client_version": version, "pcap": f"pcap/{label}.pcap", "sha256": lab.sha256(pcap),
                "requested_connections": args.repeat,
            }
        tls_srv.shutdown()
        http_srv.shutdown()

    manifest = {
        "dataset_version": os.path.basename(os.path.normpath(args.out)),
        "kind": "scenarios",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {"os": platform.platform(), "kernel": platform.release(), "machine": platform.machine(),
                        "host_os_class": "unix", "transport": "loopback", "target_host": args.host,
                        "user_agent_claims": CLAIMS},
        "labels": manifest_labels,
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"wrote {len(manifest_labels)} scenario captures to {args.out}")


if __name__ == "__main__":
    main()
