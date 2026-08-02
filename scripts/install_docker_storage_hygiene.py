#!/usr/bin/env python3
"""Install one commit-bound Docker storage-hygiene release."""
from __future__ import annotations
import argparse, hashlib, json, os, signal, stat, subprocess, sys, tempfile, time
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parents[1]
SOURCES={
 "scripts/docker_storage_hygiene.py":0o755,
 "config/docker-storage-hygiene.v1.json":0o600,
}
UNIT="heim-pc-docker-storage-hygiene"
class InstallError(RuntimeError): pass

def h(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def run(argv:list[str],cwd:Path|None=None)->subprocess.CompletedProcess[str]:
    result=subprocess.run(argv,cwd=cwd,text=True,capture_output=True,check=False)
    if result.returncode!=0: raise InstallError(f"{' '.join(argv)} failed: {(result.stderr or result.stdout)[:1000]}")
    return result

def identity()->tuple[str,bool]:
    head=run(["git","rev-parse","HEAD"],ROOT).stdout.strip(); dirty=bool(run(["git","status","--porcelain=v1","--untracked-files=all"],ROOT).stdout.strip())
    if len(head)!=40 or any(c not in "0123456789abcdef" for c in head): raise InstallError("invalid repository HEAD")
    return head,dirty

def blob(head:str,relative:str)->bytes:
    result=subprocess.run(["git","show",f"{head}:{relative}"],cwd=ROOT,capture_output=True,check=False)
    if result.returncode: raise InstallError(f"cannot read commit-bound blob: {relative}")
    return result.stdout

def safe_systemd(path:Path)->str:
    raw=str(path)
    if not path.is_absolute() or any(c.isspace() or c in "%\\\"'" for c in raw): raise InstallError(f"unsafe systemd path: {path}")
    return raw

def ensure_directory(path:Path,mode:int=0o700)->dict[str,Any]:
    if path.is_symlink(): raise InstallError(f"symlink directory: {path}")
    created=not path.exists()
    path.mkdir(parents=True,exist_ok=True,mode=mode)
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid(): raise InstallError(f"unsafe directory: {path}")
    os.chmod(path,mode)
    return {"path":str(path),"action":"created" if created else "verified","mode":format(mode,"04o")}

def atomic(path:Path,data:bytes,mode:int)->dict[str,Any]:
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink(): raise InstallError(f"symlink target: {path}")
    unchanged=path.exists() and path.read_bytes()==data and stat.S_IMODE(path.stat().st_mode)==mode
    if not unchanged:
        fd,name=tempfile.mkstemp(prefix=f".{path.name}.",dir=path.parent); temp=Path(name)
        try:
            with os.fdopen(fd,"wb") as handle: handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.chmod(temp,mode); os.replace(temp,path)
        finally: temp.unlink(missing_ok=True)
    else: os.chmod(path,mode)
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or path.read_bytes()!=data or stat.S_IMODE(info.st_mode)!=mode: raise InstallError(f"readback failed: {path}")
    return {"path":str(path),"action":"unchanged" if unchanged else "installed","mode":format(mode,"04o"),"sha256":h(data)}

def verify(paths:list[Path])->dict[str,Any]:
    result=subprocess.run(["systemd-analyze","--user","--generators=no","--man=no","verify",*[str(x) for x in paths]],text=True,capture_output=True,check=False)
    diagnostics=[line for line in result.stderr.splitlines() if any(str(path) in line for path in paths)]
    if diagnostics: raise InstallError("unit diagnostics: "+" | ".join(diagnostics[:10]))
    if result.returncode==0:return {"status":"verified","returncode":0}
    if result.returncode==-signal.SIGABRT and "Failed to allocate device monitor" in result.stderr and "Assertion '*_head == _item' failed" in result.stderr:return {"status":"host-verifier-unavailable","returncode":result.returncode}
    raise InstallError(f"unit verification failed: {(result.stderr or result.stdout)[:1000]}")

def install(home:Path,release_root:Path,apply:bool,enable:bool,start:bool,expected_head:str|None)->dict[str,Any]:
    head,dirty=identity()
    if dirty: raise InstallError("repository must be clean for commit-bound install")
    if expected_head and expected_head!=head: raise InstallError("HEAD differs from expected_head")
    release=release_root/head; release_text=safe_systemd(release); home_text=safe_systemd(home)
    release_files={release/rel:(blob(head,rel),mode) for rel,mode in SOURCES.items()}
    unit_root=home/".config/systemd/user"
    template=blob(head,f"systemd/user/{UNIT}.service.in").decode()
    service_data=template.replace("@RELEASE_ROOT@",release_text).replace("@HOME@",home_text).encode()
    if b"@RELEASE_ROOT@" in service_data or b"@HOME@" in service_data: raise InstallError("unit rendering incomplete")
    service_target=unit_root/f"{UNIT}.service"
    timer_target=unit_root/f"{UNIT}.timer"
    all_files={
        **release_files,
        service_target:(service_data,0o644),
        timer_target:(blob(head,f"systemd/user/{UNIT}.timer"),0o644),
    }
    planned=[{"path":str(path),"mode":format(mode,"04o"),"sha256":h(data)} for path,(data,mode) in all_files.items()]
    runtime_directories=[
        home/".local/state/heim-pc/docker-storage-hygiene",
        home/".local/state/heim-pc/docker-storage-hygiene/install-receipts",
    ]
    installed=[]; directories=[]; verification={"status":"not-applied"}; systemd="not-applied"
    if apply:
        for path in runtime_directories: directories.append(ensure_directory(path))
        for path,(data,mode) in all_files.items(): installed.append(atomic(path,data,mode))
        verification=verify([service_target,timer_target]); run(["systemctl","--user","daemon-reload"])
        if run(["systemctl","--user","show",f"{UNIT}.service","--property=LoadState","--value"]).stdout.strip()!="loaded": raise InstallError(f"service not loaded: {UNIT}")
        if enable:
            run(["systemctl","--user","enable","--now",f"{UNIT}.timer"])
            systemd="timer-enabled"
        else: systemd="installed"
        if start:
            run(["systemctl","--user","start",f"{UNIT}.service"])
            systemd += "+service-started"
    receipt={"schema_version":1,"kind":"heim_pc_docker_storage_hygiene_install_receipt","generated_at_unix":int(time.time()),"repository_head":head,"repository_dirty":dirty,"release_root":str(release),"apply":apply,"enable":enable,"start":start,"planned":planned,"runtime_directories":[str(path) for path in runtime_directories],"directories":directories,"installed":installed,"systemd":systemd,"unit_verification":verification,"does_not_establish":["future_timer_success","permission_to_prune_volumes","cleanup_of_active_work"]}
    receipt["receipt_sha256"]=h(json.dumps(receipt,sort_keys=True,separators=(",",":")).encode())
    if apply:
        target=home/".local/state/heim-pc/docker-storage-hygiene/install-receipts"/f"{head}.json"; atomic(target,(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode(),0o600); receipt["receipt_path"]=str(target)
    return receipt

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--home",type=Path,default=Path.home()); parser.add_argument("--release-root",type=Path,default=Path.home()/".local/lib/heim-pc/docker-storage-hygiene/releases"); parser.add_argument("--expected-head"); parser.add_argument("--apply",action="store_true"); parser.add_argument("--enable",action="store_true"); parser.add_argument("--start",action="store_true"); args=parser.parse_args()
    if (args.enable or args.start) and not args.apply: parser.error("--enable/--start require --apply")
    try: value=install(args.home.expanduser().resolve(),args.release_root.expanduser().resolve(),args.apply,args.enable,args.start,args.expected_head)
    except (InstallError,OSError,ValueError) as exc: print(json.dumps({"kind":"heim_pc_docker_storage_hygiene_install_error","error":str(exc)},sort_keys=True),file=sys.stderr); return 1
    print(json.dumps(value,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
