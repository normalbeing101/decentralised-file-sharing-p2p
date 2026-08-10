#!/usr/bin/env python3
"""Secure direct P2P file sharing with a unified CLI."""
import argparse, getpass, hashlib, json, os, socket, struct, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
BUFFER_SIZE=1024*1024; DEFAULT_PORT=5000; MAGIC=b"P2P2"; SALT_SIZE=16; NONCE_SIZE=12; MAX_FRAME=BUFFER_SIZE+NONCE_SIZE+16
RESET="\033[0m"; BOLD="\033[1m"; CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; DIM="\033[2m"
def banner():
 print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════╗\n║        P2P FILE SHARE  •  v2        ║\n╚══════════════════════════════════════╝{RESET}")
 print(f"{DIM}Direct TCP • AES-256-GCM • SHA-256{RESET}\n")
def derive_key(password,salt):
 if len(password)<8: raise ValueError("Password must contain at least 8 characters.")
 return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(password.encode())
def recv_exact(sock,size):
 data=bytearray()
 while len(data)<size:
  chunk=sock.recv(size-len(data))
  if not chunk: raise ConnectionError("Peer closed the connection unexpectedly.")
  data.extend(chunk)
 return bytes(data)
def send_frame(sock,payload):
 if len(payload)>MAX_FRAME: raise ValueError("Encrypted frame is too large.")
 sock.sendall(struct.pack("!I",len(payload))+payload)
def recv_frame(sock):
 length=struct.unpack("!I",recv_exact(sock,4))[0]
 if length==0 or length>MAX_FRAME: raise ValueError("Invalid encrypted frame size.")
 return recv_exact(sock,length)
def aad(kind,index): return MAGIC+kind+struct.pack("!Q",index)
def progress(done,total,started):
 elapsed=max(time.monotonic()-started,.001); speed=done/elapsed/(1024*1024); pct=(done/total*100) if total else 100; width=28; filled=int(width*pct/100); bar="█"*filled+"░"*(width-filled); eta=((total-done)/(speed*1024*1024)) if speed>0 and total else 0
 return f"\r{CYAN}[{bar}]{RESET} {pct:6.2f}%  {speed:7.2f} MiB/s  ETA {eta:5.1f}s"
def file_sha256(path):
 digest=hashlib.sha256()
 with path.open("rb") as file:
  while chunk:=file.read(BUFFER_SIZE): digest.update(chunk)
 return digest.hexdigest()
def send_file(host,port,file_path,password):
 if not file_path.is_file(): raise FileNotFoundError(f"File not found: {file_path}")
 size=file_path.stat().st_size; salt=os.urandom(SALT_SIZE); aes=AESGCM(derive_key(password,salt)); digest=file_sha256(file_path)
 metadata=json.dumps({"filename":file_path.name,"size":size,"sha256":digest},separators=(",",":")).encode(); nonce=os.urandom(NONCE_SIZE); enc_meta=nonce+aes.encrypt(nonce,metadata,aad(b"META",0)); started=time.monotonic()
 try:
  with socket.create_connection((host,port),timeout=15) as sock:
   sock.settimeout(60); sock.sendall(MAGIC+salt); send_frame(sock,enc_meta); sent=index=0
   with file_path.open("rb") as file:
    while chunk:=file.read(BUFFER_SIZE):
     nonce=os.urandom(NONCE_SIZE); send_frame(sock,nonce+aes.encrypt(nonce,chunk,aad(b"DATA",index))); sent+=len(chunk); index+=1; print(progress(sent,size,started),end="",flush=True)
   sock.sendall(struct.pack("!I",0))
 except (OSError,ConnectionError) as exc: raise ConnectionError(f"Transfer failed: {exc}") from exc
 print(f"\n{GREEN}✓ Sent successfully{RESET}: {file_path.name}\n  SHA-256: {digest}"); return digest
def receive_file(bind_host,port,output_dir,password,ready_callback=None):
 output_dir.mkdir(parents=True,exist_ok=True)
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
  server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); server.bind((bind_host,port)); server.listen(1)
  if ready_callback: ready_callback(server.getsockname()[1])
  conn,address=server.accept()
  with conn:
   conn.settimeout(60); print(f"{DIM}Connected from {address[0]}:{address[1]}{RESET}"); hello=recv_exact(conn,len(MAGIC)+SALT_SIZE)
   if hello[:len(MAGIC)]!=MAGIC: raise ValueError("Unknown protocol version.")
   aes=AESGCM(derive_key(password,hello[len(MAGIC):])); enc=recv_frame(conn); nonce=enc[:NONCE_SIZE]
   try: info=json.loads(aes.decrypt(nonce,enc[NONCE_SIZE:],aad(b"META",0)).decode())
   except Exception as exc: raise ValueError("Wrong password or unauthenticated metadata.") from exc
   filename=Path(str(info["filename"])).name; size=int(info["size"]); expected=str(info["sha256"])
   if size<0 or len(expected)!=64: raise ValueError("Invalid transfer metadata.")
   dest=output_dir/filename
   if dest.exists(): dest=output_dir/f"{dest.stem}_{int(time.time())}{dest.suffix}"
   digest=hashlib.sha256(); received=index=0; started=time.monotonic()
   try:
    with dest.open("wb") as output:
     while True:
      length=struct.unpack("!I",recv_exact(conn,4))[0]
      if length==0: break
      if length<=NONCE_SIZE+16 or length>MAX_FRAME: raise ValueError("Invalid encrypted data frame.")
      enc=recv_exact(conn,length); nonce=enc[:NONCE_SIZE]
      try: chunk=aes.decrypt(nonce,enc[NONCE_SIZE:],aad(b"DATA",index))
      except Exception as exc: raise ValueError("Authentication failed: wrong password or modified data.") from exc
      received+=len(chunk)
      if received>size: raise ValueError("Peer sent more data than declared.")
      digest.update(chunk); output.write(chunk); index+=1; print(progress(received,size,started),end="",flush=True)
   except Exception:
    dest.unlink(missing_ok=True); raise
   actual=digest.hexdigest()
   if received!=size or actual!=expected:
    dest.unlink(missing_ok=True); raise ValueError("SHA-256 integrity check failed; file discarded.")
   print(f"\n{GREEN}✓ Received successfully{RESET}: {dest}\n  SHA-256: {actual} [OK]"); return dest
def prompt_password():
 password=getpass.getpass("Encryption password (min 8 chars): ")
 if len(password)<8: raise ValueError("Password must contain at least 8 characters.")
 return password
def interactive():
 banner(); print(f"{BOLD}Choose a mode{RESET}\n  {CYAN}[1]{RESET} Send a file\n  {CYAN}[2]{RESET} Receive a file\n  {CYAN}[3]{RESET} Start web interface\n  {CYAN}[q]{RESET} Quit\n")
 choice=input("  Select: ").strip().lower()
 if choice=="1": send_file(input("  Receiver IP: ").strip(),int(input(f"  Port [{DEFAULT_PORT}]: ").strip() or DEFAULT_PORT),Path(input("  File path: ").strip().strip('"')),prompt_password())
 elif choice=="2": receive_file("0.0.0.0",int(input(f"  Listen port [{DEFAULT_PORT}]: ").strip() or DEFAULT_PORT),Path(input("  Output folder [received]: ").strip() or "received"),prompt_password())
 elif choice=="3": from web import run_web; run_web("127.0.0.1",8080)
 elif choice!="q": raise ValueError("Invalid selection.")
def main():
 parser=argparse.ArgumentParser(prog="p2p",description="Secure direct P2P file sharing"); sub=parser.add_subparsers(dest="command")
 s=sub.add_parser("send",help="Send a file"); s.add_argument("host"); s.add_argument("file",type=Path); s.add_argument("--port",type=int,default=DEFAULT_PORT)
 r=sub.add_parser("receive",help="Receive a file"); r.add_argument("--host",default="0.0.0.0"); r.add_argument("--port",type=int,default=DEFAULT_PORT); r.add_argument("--output",type=Path,default=Path("received"))
 w=sub.add_parser("web",help="Start local web interface"); w.add_argument("--host",default="127.0.0.1"); w.add_argument("--port",type=int,default=8080)
 args=parser.parse_args()
 try:
  if not args.command: interactive()
  elif args.command=="send": send_file(args.host,args.port,args.file,prompt_password())
  elif args.command=="receive": receive_file(args.host,args.port,args.output,prompt_password())
  else: from web import run_web; run_web(args.host,args.port)
 except KeyboardInterrupt: print(f"\n{YELLOW}Cancelled.{RESET}")
 except (ValueError,FileNotFoundError,ConnectionError,OSError) as exc: print(f"\n{RED}✗ {exc}{RESET}",file=sys.stderr); raise SystemExit(1)
if __name__=="__main__": main()
