"""One-click local judge session. No downloads, provider calls or automatic inference."""
import argparse
import errno
import os
import secrets
import sys
import threading
import webbrowser
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent


def judge_environment(data_directory, enable_local_models=False):
    """Only this process changes. Ignore inherited/provider settings and local .env."""
    for name in list(os.environ):
        if name.startswith('SZ_') or name in {'RED_URL', 'BLUE_URL', 'TARGET_URL'}:
            os.environ.pop(name, None)
    os.environ.update(SZ_MODE='local', SZ_MODEL='', SZ_DATA=str(data_directory),
                      SZ_JUDGE_MODE='1', SZ_JUDGE_LOCAL_MODELS='1' if enable_local_models else '0')


def create_judge_server(port=8000, data_directory=None, enable_local_models=False):
    if sys.version_info < (3, 11):
        raise RuntimeError('Python 3.11 or newer is required.')
    data_directory = Path(data_directory or ROOT / '.judge-data').resolve()
    judge_environment(data_directory, enable_local_models)
    from http.server import ThreadingHTTPServer
    from engine import Audit
    from server import make_handler
    access_code = secrets.token_urlsafe(24)
    handler = make_handler('gateway', Audit(data_directory), access_code)
    candidates = [0] if port == 0 else list(range(port, min(port + 10, 65536))) + [0]
    for candidate in candidates:
        try:
            server = ThreadingHTTPServer(('127.0.0.1', candidate), handler)
            server.daemon_threads = True
            break
        except OSError as error:
            if error.errno not in {errno.EADDRINUSE, errno.EACCES} and getattr(error, 'winerror', None) not in {10013, 10048}:
                raise
    else:
        raise RuntimeError('No local port could be opened. Check your local firewall permissions.')
    address = f'http://127.0.0.1:{server.server_port}'
    # Fragments do not enter HTTP requests. The UI consumes and removes this
    # credential immediately, retaining it only in this tab's session storage.
    browser_url = address + '/#' + urlencode({'connect': access_code, 'page': 'judge'})
    return server, access_code, address, browser_url


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--no-browser', action='store_true', help='Print the address and key without opening a browser.')
    parser.add_argument('--data-dir', type=Path, help='Separate evaluation directory. Default: .judge-data.')
    parser.add_argument('--enable-local-models', action='store_true',
                        help='Explicitly allow local inference after completing JUDGE_GUIDE.md setup.')
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error('Port must be between 0 and 65535.')
    try:
        server, key, address, browser_url = create_judge_server(args.port, args.data_dir, args.enable_local_models)
    except (OSError, RuntimeError) as error:
        print(f'Could not start Sandbox Zero: {error}', file=sys.stderr)
        return 1
    print('\nSANDBOX ZERO / OFFGRID DEV / JUDGE QUICKSTART', flush=True)
    print(f'Local address: {address}/#judge\nAccess key:    {key}', flush=True)
    print(f'Python:        {sys.executable}', flush=True)
    print('Core fixture demo is ready. No API key, Docker or model download is needed.', flush=True)
    print('Qwen: recorded on our machine using Ollama. Another machine may behave differently.', flush=True)
    print('Local inference: ' + ('explicitly enabled; runs only when you click a model action.' if args.enable_local_models
                                     else 'disabled for this session. Optional setup: JUDGE_GUIDE.md.'), flush=True)
    print('Judge runs use .judge-data (or your --data-dir); original .data evidence stays untouched.', flush=True)
    print('Keep this window open. Press Ctrl+C to stop the server.\n', flush=True)
    if not args.no_browser:
        def open_browser():
            try:
                if webbrowser.open(browser_url):
                    return
            except (OSError, webbrowser.Error):
                pass
            print(f'Browser did not open. Visit {address}/#judge and paste the access key above.', flush=True)
        threading.Thread(target=open_browser, daemon=True).start()
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        print('\nSandbox Zero stopped.', flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
