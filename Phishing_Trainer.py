#!/usr/bin/env python3
# Phishing Trainer MVP with admin page showing logs
# Save as Phishing_Trainer.py

import argparse, uuid, csv, os, urllib.parse, html
from http.server import HTTPServer, BaseHTTPRequestHandler
from email.message import EmailMessage
from datetime import datetime

CLICK_LOG = "clicks.csv"
EMAIL_MAP = "emails.csv"
CREDS_LOG = "creds.csv"
MAX_ROWS_ADMIN = 50

LANDING_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Important Notice</title></head>
<body>
<h2>Important Account Notice</h2>
<p>This is a simulated phishing training page. Your click was logged.</p>
<p><b>Tracking ID:</b> {uid}</p>

<form method="post" action="/submit">
  <label>Email: <input name="email" type="email" required></label><br><br>
  <label>Password: <input name="password" type="password" required></label><br><br>
  <input type="hidden" name="uid" value="{uid}">
  <button type="submit">Submit</button>
</form>

<form method="post" action="/report" style="margin-top:15px;">
  <button type="submit">Report this as phishing</button>
</form>

<p style="margin-top:20px;font-size:0.9em;"><a href="/admin" target="_blank">View admin logs (local only)</a></p>
</body></html>
"""

ADMIN_HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Admin - Logs</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;padding:10px}}
table{{border-collapse:collapse;width:100%;margin-bottom:20px}}
th,td{{border:1px solid #ddd;padding:6px 8px;font-size:13px}}
th{{background:#f3f3f3;text-align:left}}
h2{{margin-top:0}}
.small{{font-size:0.9em;color:#555}}
</style>
</head><body>
<h2>Phishing Trainer — Admin Logs</h2>
<p class="small">Showing up to {max_rows} most recent rows from each log file. This page is local-only if you run on 127.0.0.1.</p>

<h3>Clicks (clicks.csv)</h3>
{clicks_table}

<h3>Credential submissions (creds.csv)</h3>
{creds_table}

<h3>Emails generated (emails.csv)</h3>
{emails_table}

</body></html>
"""

def tail_csv_rows(path, max_rows):
    """Read CSV file and return last max_rows rows as list-of-lists including header (if present)."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, newline='', encoding='utf-8') as f:
            reader = list(csv.reader(f))
            if not reader:
                return []
            # If header row exists (assume first row is header if any non-digit string in row)
            header = reader[0]
            body = reader[1:] if len(reader) > 1 else []
            last = body[-max_rows:] if len(body) > max_rows else body
            return [header] + last
    except Exception:
        # fallback: try to read raw lines
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.read().splitlines()
                if not lines:
                    return []
                header = lines[0].split(',')
                body = [l.split(',') for l in lines[1:]]
                last = body[-max_rows:] if len(body) > max_rows else body
                return [header] + last
        except Exception:
            return []

def html_table_from_rows(rows):
    """Convert CSV rows (list-of-lists) to an HTML table safely escaped."""
    if rows is None:
        return "<p><i>File not found.</i></p>"
    if rows == []:
        return "<p><i>No rows.</i></p>"
    header = rows[0]
    body = rows[1:] if len(rows) > 1 else []
    out = ["<table><thead><tr>"]
    for col in header:
        out.append(f"<th>{html.escape(str(col))}</th>")
    out.append("</tr></thead><tbody>")
    for r in reversed(body):  # show newest first
        out.append("<tr>")
        for c in r:
            out.append(f"<td>{html.escape(str(c))}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)

class TrackHandler(BaseHTTPRequestHandler):
    def log_click(self, uid):
        ts = datetime.utcnow().isoformat()
        ip = self.client_address[0]
        header = not os.path.exists(CLICK_LOG)
        with open(CLICK_LOG, "a", newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            if header:
                w.writerow(["timestamp_utc","uid","ip","user_agent"])
            w.writerow([ts, uid, ip, self.headers.get('User-Agent','')])

    def log_creds(self, uid, email, password):
        ts = datetime.utcnow().isoformat()
        ip = self.client_address[0]
        header = not os.path.exists(CREDS_LOG)
        with open(CREDS_LOG, "a", newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            if header:
                w.writerow(["timestamp_utc","uid","email","password","ip"])
            w.writerow([ts, uid, email, password, ip])

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/track") or path == "/":
            qs = urllib.parse.parse_qs(parsed.query)
            uid = qs.get("uid", ["unknown"])[0]
            self.log_click(uid)
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(LANDING_HTML.format(uid=html.escape(uid)).encode('utf-8'))
            return

        if path == "/admin":
            # build admin page
            clicks_rows = tail_csv_rows(CLICK_LOG, MAX_ROWS_ADMIN)
            creds_rows = tail_csv_rows(CREDS_LOG, MAX_ROWS_ADMIN)
            emails_rows = tail_csv_rows(EMAIL_MAP, MAX_ROWS_ADMIN)
            clicks_table = html_table_from_rows(clicks_rows)
            creds_table = html_table_from_rows(creds_rows)
            emails_table = html_table_from_rows(emails_rows)
            body = ADMIN_HTML_TEMPLATE.format(
                max_rows=MAX_ROWS_ADMIN,
                clicks_table=clicks_table,
                creds_table=creds_table,
                emails_table=emails_table
            )
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
            return

        # default 404
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        # read body
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        parsed_path = urllib.parse.urlparse(self.path)

        if parsed_path.path == "/submit":
            data = urllib.parse.parse_qs(body.decode('utf-8'))
            uid = data.get('uid', ['unknown'])[0]
            email = data.get('email', [''])[0]
            password = data.get('password', [''])[0]
            # Log both click and creds safely to local files
            self.log_click(uid)
            self.log_creds(uid, email, password)
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h3>Thank you. Your response was recorded for training.</h3></body></html>")
            return

        if parsed_path.path == "/report":
            # report button: log click with reported flag
            self.log_click("reported")
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h3>Thanks — you reported this as phishing.</h3></body></html>")
            return

        # fallback
        self.send_response(404)
        self.end_headers()

def run_server(host, port):
    print(f"Starting tracker on http://{host}:{port}  (logs -> {CLICK_LOG}, {CREDS_LOG})")
    server = HTTPServer((host, port), TrackHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")

def gen_email(recipient, sender, subject, body_template, host, port):
    uid = str(uuid.uuid4())
    link = f"http://{host}:{port}/track?uid={uid}"
    body = body_template.format(link=link, uid=uid)
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.set_content(body)
    filename = f"phish_{uid}.eml"
    with open(filename, "wb") as f:
        f.write(msg.as_bytes())

    header = not os.path.exists(EMAIL_MAP)
    with open(EMAIL_MAP, "a", newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        if header:
            w.writerow(["uid","recipient","sender","subject","filename","timestamp_utc"])
        w.writerow([uid, recipient, sender, subject, filename, datetime.utcnow().isoformat()])

    print(f"Wrote {filename}")
    print(f"Tracking link: {link}")

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)

    s_run = sub.add_parser('serve', help='Run tracker server')
    s_run.add_argument('--host', default='127.0.0.1')
    s_run.add_argument('--port', default=8000, type=int)

    s_gen = sub.add_parser('gen-email', help='Generate a test .eml file linking to tracker')
    s_gen.add_argument('--recipient', required=True)
    s_gen.add_argument('--sender', required=True)
    s_gen.add_argument('--subject', required=True)
    s_gen.add_argument('--body', required=True, help='Use {link} in body where link should be inserted')
    s_gen.add_argument('--host', default='127.0.0.1')
    s_gen.add_argument('--port', default=8000, type=int)

    args = p.parse_args()
    if args.cmd == 'serve':
        run_server(args.host, args.port)
    elif args.cmd == 'gen-email':
        gen_email(args.recipient, args.sender, args.subject, args.body, args.host, args.port)

if __name__ == "__main__":
    main()
