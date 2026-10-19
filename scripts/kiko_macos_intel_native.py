"""Intel Mac native15->16 binary-only fixture, no private source or UI input."""
import ast
from contextlib import closing
import ctypes as c
from datetime import datetime, timezone
from hashlib import sha256
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
from threading import Event, Thread
import time
from urllib.parse import urlparse
import httpx
import psutil
import requests
from PyInstaller.archive.readers import CArchiveReader

HEAD='f78b1ae89b7fbf4e584efc83b74ddfaa2eaaf98f'
assert sys.platform=='darwin' and platform.machine()=='x86_64' and sys.version_info[:2]==(3,12)
assert psutil.cpu_count(logical=False)>=4 and psutil.virtual_memory().total>=8*1024**3
root=Path(os.environ['RUNNER_TEMP']).resolve()/'kiko-intel-native16'
assert not root.exists() and shutil.disk_usage(root.parent).free>=16*1024**3
root.mkdir(); evidence=root/'evidence';evidence.mkdir()
download_urls=json.loads(os.environ['KIKO_NATIVE_QA_DOWNLOADS'])
resource_stop=Event()
# Reuse only public QA utility definitions, not Linux action/body or product source.
public_basis=Path(__file__).with_name('kiko_linux_arm_native.py')
tree=ast.parse(public_basis.read_text())
names={'digest','download','FrozenAppImporter','guard','record','protection'}
nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
assert {n.name for n in nodes}==names
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(public_basis)+'[utilities-only]','exec'))
(evidence/'preflight.json').write_text(json.dumps(dict(sourceCommit=HEAD,physicalCores=psutil.cpu_count(logical=False),
    memoryBytes=psutil.virtual_memory().total,level='native-Intel-standard-public-runner',osTrustBypassed=False)))
Thread(target=guard,daemon=True).start()
with socket.socket() as probe:assert probe.connect_ex(('127.0.0.1',8765))!=0
package=download(655605075,'KayuLocalAssistant-macos-x64.dmg','a0be7949400dd8e50a863b4c6322e67df3820ac79d426aaf9a698c2dbc60e80e')
old_package=download(int(os.environ['KIKO_MAC_BASELINE_ASSET']),'original15-macos-x64.dmg','00a8571c6f799f67e767df2b74d5c5d59b93d22f894c65c243a90f74d266f7f6')
def mount(package,name):
    target=root/name;target.mkdir()
    subprocess.run(['/usr/bin/hdiutil','attach','-nobrowse','-readonly','-mountpoint',str(target),str(package),'-quiet'],check=True,timeout=120)
    apps=list(target.glob('*.app'));assert len(apps)==1 and apps[0].name in ('Kiko.app','Kayu.app')
    return target,apps[0]
candidate_mount,candidate_app=mount(package,'candidate-mount')
old_mount,old_app=mount(old_package,'old-mount')
candidate=candidate_app/'Contents/MacOS'
assert digest(candidate/'KayuLocalAssistant')=='eb0627268e5312cf1cdbd798a3ff047a91f921a44bd1a00a97134f9eb8faa99d'
pyz=CArchiveReader(str(candidate/'KayuLocalAssistant')).open_embedded_archive('PYZ.pyz')
sys.meta_path.insert(0,FrozenAppImporter())
from app.desktop.update_receipt import UpdateReceiptStore
from app.desktop.update_worker import (NativeUpdateOperations,WorkerTicket,installed_version,
    prepare_worker,launch_worker,tree_fingerprint)
from app.desktop.update_lifecycle import ParticipantRecord,UpdateCoordinator,process_identity
from app.desktop.updater import DesktopUpdateAsset

work=root/'fixture';work.mkdir();program=work/'Kiko.app'
subprocess.run(['/usr/bin/ditto','--rsrc','--extattr',str(old_app),str(program)],check=True,timeout=600)
assert tree_fingerprint(program)==tree_fingerprint(old_app)
exe=program/'Contents/MacOS/KayuLocalAssistant'
assert digest(exe)=='6222ebc1ed33841ec614340711ef93d9c5e23f036cc784a83ce14156ebc61917'
assert installed_version(program,'macos-x64')=='0.3.15'
data=work/'data';(data/'database').mkdir(parents=True);(data/'files').mkdir()
os.environ.update(KAYU_LOCAL_DATA_DIR=str(data),OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
original=data/'files/synthetic-update-original.txt';original.write_bytes(b'Synthetic native Intel original.\n')
settings=data/'synthetic-settings.json';settings.write_bytes(b'{"synthetic":"preserve"}\n')
with sqlite3.connect(data/'database/shunao.db') as db:
    db.execute('CREATE TABLE kiko_upgrade_fixture(id INTEGER PRIMARY KEY,value TEXT NOT NULL)')
    db.execute('INSERT INTO kiko_upgrade_fixture VALUES(1,?)',('preserve-native-intel',));db.commit()
store=UpdateReceiptStore(data)
state=dict(sourceCommit=HEAD,version='0.3.16',platform='macos-x64',complete=False,
    level='native-Intel-standard-public-runner',physicalDeviceAcceptance=False,modelCalls=0,
    physicalGuiInput=False,privateProductSourceUploaded=False,osTrustBypassed=False,
    browserQuarantineOrOsTrustedInstallClaimed=False,original15ExecutableSha256=digest(exe),phases=[])

cf=c.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
cg=c.CDLL('/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics')
cg.CGWindowListCopyWindowInfo.argtypes=[c.c_uint32,c.c_uint32];cg.CGWindowListCopyWindowInfo.restype=c.c_void_p
cf.CFArrayGetCount.argtypes=[c.c_void_p];cf.CFArrayGetCount.restype=c.c_long
cf.CFArrayGetValueAtIndex.argtypes=[c.c_void_p,c.c_long];cf.CFArrayGetValueAtIndex.restype=c.c_void_p
cf.CFDictionaryGetValue.argtypes=[c.c_void_p,c.c_void_p];cf.CFDictionaryGetValue.restype=c.c_void_p
cf.CFNumberGetValue.argtypes=[c.c_void_p,c.c_int,c.c_void_p];cf.CFNumberGetValue.restype=c.c_bool
cf.CFRelease.argtypes=[c.c_void_p]
def windows(pid):
    rows=cg.CGWindowListCopyWindowInfo(0,0);assert rows
    def number(row,key):
        value=cf.CFDictionaryGetValue(row,c.c_void_p.in_dll(cg,key).value);result=c.c_longlong()
        return result.value if value and cf.CFNumberGetValue(value,4,c.byref(result)) else None
    try:
        return sorted(number(cf.CFArrayGetValueAtIndex(rows,i),'kCGWindowNumber')
            for i in range(cf.CFArrayGetCount(rows))
            if number(cf.CFArrayGetValueAtIndex(rows,i),'kCGWindowOwnerPID')==pid
            and number(cf.CFArrayGetValueAtIndex(rows,i),'kCGWindowLayer')==0)
    finally:cf.CFRelease(rows)
def own_listener(process):
    try:return any(row.status=='LISTEN' and row.laddr.port==8765 for row in process.net_connections('tcp'))
    except psutil.AccessDenied:
        result=subprocess.run(['/usr/sbin/lsof','-nP','-a','-p',str(process.pid),'-iTCP:8765','-sTCP:LISTEN'],capture_output=True,timeout=3)
        return result.returncode==0 and b'LISTEN' in result.stdout
def observe(version,timeout=100):
    deadline=time.monotonic()+timeout
    with httpx.Client(trust_env=False,timeout=1) as client:
        while time.monotonic()<deadline:
            for process in psutil.process_iter(['exe'],ad_value=None):
                try:
                    if process.info['exe']!=str(exe) or not process.is_running() or process.status()==psutil.STATUS_ZOMBIE:continue
                    assert process.username()==psutil.Process().username()
                    native=windows(process.pid)
                    if not native or not own_listener(process):continue
                    status=client.get('http://127.0.0.1:8765/local-assistant/v1/status').json()
                    if status.get('state')!='ready' or status.get('contentOperationsEnabled') is not True:continue
                    identity=process_identity(process);participants=[]
                    for path in (store._root/'participants').glob('*.json'):
                        row=ParticipantRecord.model_validate(store._read(path))
                        if row.identity==identity and row.role=='window' and row.idle is True and 0<=time.time()-row.updated_at<=2:
                            participants.append(row.model_dump(by_alias=True))
                    if participants:
                        assert installed_version(program,'macos-x64')==version
                        return dict(version=version,identity=identity.model_dump(by_alias=True),nativeWindows=native,
                            ownListener=True,freshActualSignedFrontendIdle=participants,executableSha256=digest(exe))
                except (psutil.NoSuchProcess,psutil.AccessDenied,httpx.HTTPError,ValueError):continue
            time.sleep(.2)
    raise RuntimeError('Actual Intel service/window/signed frontend idle not ready')

asset=DesktopUpdateAsset(fileName=package.name,url='https://github.com/liudingshu/liudingshu.github.io/releases/download/desktop-v0.3.16/'+package.name,
    sha256=digest(package),byteSize=package.stat().st_size,installerKind='macos-dmg')
download_path=store._root/'downloads/0.3.16'/package.name;download_path.parent.mkdir(parents=True)
os.link(package,download_path)
def prepare():
    run=store.begin('0.3.15','0.3.16','macos-x64',asset.sha256)
    prepared=prepare_worker(data,run,download_path,asset,executable=exe)
    return run,prepared,NativeUpdateOperations(WorkerTicket.model_validate(store._read(prepared.ticket_path)),store)
try:
    with (evidence/'old.stdout').open('xb') as out,(evidence/'old.stderr').open('xb') as err:
        subprocess.Popen([str(exe)],cwd=program,stdout=out,stderr=err,close_fds=True)
    record('actual-original15-native-Intel-window-idle',observation=observe('0.3.15'))
    before=protection();old_tree=tree_fingerprint(program)[0]
    record('exact-original15-program-and-protected-data',treeSha256=old_tree,protection=before)
    run,prepared,ops=prepare()
    with store._locked('worker.lock'):
        store.advance(run.run_id,'quiescing');coordinator=UpdateCoordinator(data,exe)
        participants=coordinator.request_shutdown(run.run_id);coordinator.wait_for_exit(participants,before_exit=ops.snapshot)
        store.advance(run.run_id,'installing');code=ops.install();assert code==0
        store.advance(run.run_id,'verifying',installer_exit_code=code)
        proof=ops.verify_new();assert proof.version=='0.3.16'
        record('actual16-native-Intel-boot-before-fault',bootProof=proof.model_dump(by_alias=True))
        store.advance(run.run_id,'failed',error_code='DESKTOP_UPDATE_INTERRUPTED')
        old_proof=ops.recover();assert old_proof.version=='0.3.15' and tree_fingerprint(program)[0]==old_tree
        rolled=store.advance(run.run_id,'rolledBack',boot_version=old_proof.version,boot_id=old_proof.boot_id)
        observation=observe('0.3.15');assert protection()==before
        record('actual15-Intel-full-program-data-recovery',receipt=rolled.model_dump(by_alias=True),
            bootProof=old_proof.model_dump(by_alias=True),observation=observation)
    run,prepared,ops=prepare();launch_worker(prepared,data)
    record('actual-original15-frozen-Mac-worker-dispatched',runId=run.run_id)
    deadline=time.monotonic()+500
    while time.monotonic()<deadline:
        completed=store.load();assert completed.run_id==run.run_id
        if completed.stage in ('completed','rolledBack'):break
        time.sleep(.25)
    assert completed.stage=='completed',completed.model_dump(by_alias=True)
    observation=observe('0.3.16');assert protection()==before
    state.update(complete=True,actualInstallerReceipt=completed.model_dump(by_alias=True),
        actualReopenedNewest=observation,protectionBefore=before,protectionAfter=protection(),
        auditedVolatileColumnsExcluded=['app_users.updated_at','categories.updated_at'])
    record('native-Intel-install-recovery-newest-reopen-accepted')
    (evidence/'acceptance-macos-x64.json').write_text(json.dumps(state,indent=2))
except BaseException as error:
    state['failure']=dict(errorClass=type(error).__name__,fixedError=getattr(error,'code',None),resourceStop=resource_stop.is_set())
    (evidence/'failed.json').write_text(json.dumps(state,indent=2));raise
finally:
    for mounted in (old_mount,candidate_mount):
        subprocess.run(['/usr/bin/hdiutil','detach',str(mounted),'-quiet'],check=False,timeout=30)
