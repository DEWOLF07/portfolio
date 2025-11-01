#!/usr/bin/env python3
import argparse, uuid, csv, os, urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from email.message import EmailMessage
from datetime import datetime
CLICK_LOG="clicks.csv"; EMAIL_MAP="emails.csv"
LANDING_HTML='''<!doctype html><html><head><meta charset="utf-8"><title>Notice</title></head><body><h2>Simulated Training Page</h2><p>Your click was logged. Tracking ID: {uid}</p><form method="post" action="/report"><button type="submit">Report</button></form></body></html>'''
class TrackHandler(BaseHTTPRequestHandler):
    def log_click(self, uid):
        ts=datetime.utcnow().isoformat(); ip=self.client_address[0]; header=not os.path.exists(CLICK_LOG)
        with open(CLICK_LOG,"a",newline='',encoding='utf-8') as f:
            w=csv.writer(f)
            if header: w.writerow(["timestamp_utc","uid","ip","user_agent"])
            w.writerow([ts, uid, ip, self.headers.get('User-Agent','')])
    def do_GET(self):
        parsed=urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/track") or parsed.path=="/":
            qs=urllib.parse.parse_qs(parsed.query); uid=qs.get("uid",["unknown"])[0]; self.log_click(uid)
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            self.wfile.write(LANDING_HTML.format(uid=uid).encode('utf-8'))
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path=="/report":
            _=self.rfile.read(int(self.headers.get('content-length',0))) if int(self.headers.get('content-length',0))>0 else b''
            self.log_click("reported"); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            self.wfile.write(b"<html><body><h3>Thank you. This was a simulation.</h3></body></html>")
        else:
            self.send_response(404); self.end_headers()
def run_server(host,port):
    print(f"Starting tracker on http://{host}:{port}  (logs -> {CLICK_LOG})"); server=HTTPServer((host,port),TrackHandler)
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nServer stopped")
def gen_email(recipient,sender,subject,body_template,host,port):
    uid=str(uuid.uuid4()); link=f"http://{host}:{port}/track?uid={uid}"; body=body_template.format(link=link,uid=uid)
    msg=EmailMessage(); msg['From']=sender; msg['To']=recipient; msg['Subject']=subject; msg.set_content(body)
    filename=f"phish_{uid}.eml"
    with open(filename,"wb") as f: f.write(msg.as_bytes())
    header=not os.path.exists(EMAIL_MAP)
    with open(EMAIL_MAP,"a",newline='',encoding='utf-8') as f:
        w=csv.writer(f)
        if header: w.writerow(["uid","recipient","sender","subject","filename","timestamp_utc"])
        w.writerow([uid,recipient,sender,subject,filename,datetime.utcnow().isoformat()])
    print(f"Wrote {filename}\nTracking link: {link}")
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('serve'); s.add_argument('--host',default='127.0.0.1'); s.add_argument('--port',type=int,default=8000)
    g=sub.add_parser('gen-email'); g.add_argument('--recipient',required=True); g.add_argument('--sender',required=True)
    g.add_argument('--subject',required=True); g.add_argument('--body',required=True); g.add_argument('--host',default='127.0.0.1'); g.add_argument('--port',type=int,default=8000)
    args=p.parse_args()
    if args.cmd=='serve': run_server(args.host,args.port)
    elif args.cmd=='gen-email': gen_email(args.recipient,args.sender,args.subject,args.body,args.host,args.port)
if __name__=="__main__": main()
