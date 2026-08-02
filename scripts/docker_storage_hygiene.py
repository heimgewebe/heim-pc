#!/usr/bin/env python3
"""Age-bounded Docker cleanup that deliberately never prunes volumes."""
from __future__ import annotations
import argparse, fcntl, hashlib, json, os, shutil, subprocess, sys, time
from pathlib import Path
from typing import Any

class DockerHygieneError(RuntimeError): pass

def canonical(value: Any)->bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def digest(value: Any)->str: return hashlib.sha256(canonical(value)).hexdigest()

def atomic_json(path: Path,value: dict[str,Any])->None:
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            json.dump(value,handle,sort_keys=True,indent=2); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp,path)
    finally:
        try: tmp.unlink()
        except FileNotFoundError: pass

def load_policy(path: Path)->dict[str,Any]:
    try: value=json.loads(path.read_text())
    except (OSError,json.JSONDecodeError) as exc: raise DockerHygieneError(f"cannot load policy: {exc}") from exc
    expected={"schema_version","kind","minimum_unused_age_hours","automatic_gc_authorized","operations","volume_prune_authorized","named_volumes_preserved","max_output_bytes_per_command","command_timeout_seconds","max_receipts"}
    if set(value)!=expected or value["schema_version"]!=1 or value["kind"]!="heim_pc.docker_storage_hygiene_policy": raise DockerHygieneError("unexpected Docker hygiene policy")
    if value["operations"] != ["container","image","builder","network"]: raise DockerHygieneError("Docker operations differ from the bounded contract")
    if value["automatic_gc_authorized"] is not True or value["volume_prune_authorized"] is not False or value["named_volumes_preserved"] is not True: raise DockerHygieneError("Docker volume-preservation contract is invalid")
    for key in ("minimum_unused_age_hours","max_output_bytes_per_command","command_timeout_seconds","max_receipts"):
        item=value[key]
        if isinstance(item,bool) or not isinstance(item,int) or item<1: raise DockerHygieneError(f"invalid policy value: {key}")
    return value

def plan(policy: dict[str,Any], docker: str)->dict[str,Any]:
    age=f"until={policy['minimum_unused_age_hours']}h"
    commands=[
        [docker,"container","prune","-f","--filter",age],
        [docker,"image","prune","-a","-f","--filter",age],
        [docker,"builder","prune","-a","-f","--filter",age],
        [docker,"network","prune","-f","--filter",age],
    ]
    if any("volume" in command for argv in commands for command in argv): raise DockerHygieneError("volume prune entered the Docker plan")
    material={"schema_version":1,"kind":"heim_pc.docker_storage_hygiene_plan","policy_sha256":digest(policy),"commands":commands,"volume_prune_authorized":False,"named_volumes_preserved":True}
    return {**material,"plan_sha256":digest(material)}

def validate_plan(plan_value:dict[str,Any],policy:dict[str,Any])->None:
    if not isinstance(plan_value,dict):
        raise DockerHygieneError("Docker plan is not an object")
    supplied=plan_value.get("plan_sha256")
    material=dict(plan_value)
    material.pop("plan_sha256",None)
    if not isinstance(supplied,str) or digest(material)!=supplied:
        raise DockerHygieneError("Docker plan hash is invalid")
    commands=plan_value.get("commands")
    if (
        not isinstance(commands,list)
        or not commands
        or not isinstance(commands[0],list)
        or not commands[0]
        or not isinstance(commands[0][0],str)
        or not Path(commands[0][0]).is_absolute()
    ):
        raise DockerHygieneError("Docker plan command shape is invalid")
    expected=plan(policy,commands[0][0])
    if plan_value!=expected:
        raise DockerHygieneError("Docker plan differs from the current policy")

def run_command(argv:list[str],policy:dict[str,Any])->dict[str,Any]:
    try: result=subprocess.run(argv,text=True,capture_output=True,timeout=policy["command_timeout_seconds"],check=False)
    except (OSError,subprocess.TimeoutExpired) as exc: return {"argv":argv,"returncode":None,"error":type(exc).__name__}
    limit=policy["max_output_bytes_per_command"]
    return {"argv":argv,"returncode":result.returncode,"stdout":result.stdout[:limit],"stderr":result.stderr[:limit],"stdout_truncated":len(result.stdout)>limit,"stderr_truncated":len(result.stderr)>limit}

def apply(plan_value:dict[str,Any],policy:dict[str,Any],state:Path)->dict[str,Any]:
    validate_plan(plan_value,policy)
    before=run_command([plan_value["commands"][0][0],"system","df"],policy)
    commands=[run_command(list(argv),policy) for argv in plan_value["commands"]]
    after=run_command([plan_value["commands"][0][0],"system","df"],policy)
    receipt={"schema_version":1,"kind":"heim_pc.docker_storage_hygiene_receipt","completed_at_unix":int(time.time()),"plan_sha256":plan_value["plan_sha256"],"commands":commands,"before":before,"after":after,"named_volumes_preserved":True,"volume_prune_executed":False,"success":all(item.get("returncode")==0 for item in commands)}
    receipt["receipt_sha256"]=digest(receipt); atomic_json(state/f"{receipt['completed_at_unix']}.json",receipt)
    return receipt

def ensure_state_directory(path:Path)->None:
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid!=os.getuid():
        raise DockerHygieneError("Docker hygiene state directory is unsafe")
    os.chmod(path,0o700)

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--policy",type=Path,required=True); parser.add_argument("--home",type=Path,default=Path.home()); parser.add_argument("--apply",action="store_true"); args=parser.parse_args()
    policy=load_policy(args.policy); docker=shutil.which("docker")
    if not docker or not Path(docker).is_absolute(): raise DockerHygieneError("docker executable is unavailable")
    state=args.home.resolve()/".local/state/heim-pc/docker-storage-hygiene"; ensure_state_directory(state)
    lock=os.open(state/"gc.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc: raise DockerHygieneError("Docker hygiene already running") from exc
        planned=plan(policy,docker); receipt=apply(planned,policy,state) if args.apply else None
        files=sorted(state.glob("[0-9]*.json"),key=lambda p:p.name)
        for old in files[:-policy["max_receipts"]]: old.unlink(missing_ok=True)
        print(json.dumps({"plan":planned,"apply":receipt},sort_keys=True)); return 0 if receipt is None or receipt["success"] else 1
    finally: os.close(lock)
if __name__=="__main__":
    try: raise SystemExit(main())
    except DockerHygieneError as exc: print(json.dumps({"error":str(exc)}),file=sys.stderr); raise SystemExit(2)
