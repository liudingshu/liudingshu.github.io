"""Native binary-only QA. No private source, model calls or UI input."""
import ctypes as c
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
from threading import Event, Thread
import time
from urllib.parse import urlparse
import zipfile
import httpx
import psutil
import requests
from PyInstaller.archive.readers import CArchiveReader

HEAD = 'f78b1ae89b7fbf4e584efc83b74ddfaa2eaaf98f'
PACKAGE_SHA = 'e1f1d5cb962dd83c7111553b35a2f44b0d1180daaa509dc078480ed356eeac41'
EXE_SHA = 'db7efa074e30caaffedd9a6b3383b19b596d039fd134193b5c6964c51a04f3e3'
DELTA_SHA = '9df41f6d08ad014fb50a5410bac311901c4151d5abe690c453f6daef69b7b44a'
assert sys.version_info[:2] == (3, 12) and sys.platform == 'linux'
assert platform.machine() == 'aarch64' and psutil.cpu_count(logical=False) >= 4
assert psutil.virtual_memory().total >= 8 * 1024**3
root = Path(os.environ['RUNNER_TEMP']).resolve() / 'kiko-arm-native16'
assert not root.exists() and shutil.disk_usage(root.parent).free >= 16 * 1024**3
root.mkdir()
evidence = root / 'evidence'; evidence.mkdir()
(evidence/'preflight.json').write_text(json.dumps(dict(sourceCommit=HEAD,phase='real-host-gate-passed',
    physicalCores=psutil.cpu_count(logical=False),totalMemoryBytes=psutil.virtual_memory().total)))
download_urls = json.loads(os.environ['KIKO_NATIVE_QA_DOWNLOADS'])
resource_stop = Event()
def guard():
    bad = 0
    while not resource_stop.wait(3):
        sample = dict(availablePhysical=psutil.virtual_memory().available,
            diskFree=shutil.disk_usage(root).free, epoch=time.time())
        bad = bad + 1 if sample['availablePhysical'] < 512*1024**2 or sample['diskFree'] < 2*1024**3 else 0
        if bad >= 3:
            (evidence/'resource-stop.json').write_text(json.dumps(sample))
            resource_stop.set()
            # Only exact synthetic-fixture images owned by this runner user.
            for process in psutil.process_iter(['exe'], ad_value=None):
                try:
                    image = process.info['exe']
                    if image and Path(image).is_relative_to(root) and process.username() == psutil.Process().username():
                        born = process.create_time()
                        if process.is_running() and process.create_time() == born: process.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            return
Thread(target=guard, daemon=True).start()
with socket.socket() as probe:
    assert probe.connect_ex(('127.0.0.1', 8765)) != 0

def digest(path):
    result = sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''): result.update(block)
    return result.hexdigest()

def download(asset_id, name, expected):
    target = root / name
    url = download_urls[str(asset_id)]
    assert urlparse(url).scheme == 'https' and urlparse(url).hostname == 'release-assets.githubusercontent.com'
    try:
        with requests.get(url, stream=True, timeout=(30, 90)) as response:
            if response.status_code != 200: raise RuntimeError('Limited asset download rejected: ' + str(response.status_code))
            with target.open('xb') as out:
                for block in response.iter_content(4 * 1024**2): out.write(block)
    except requests.RequestException:
        raise RuntimeError('Limited binary download transport failed; URL withheld') from None
    assert digest(target) == expected
    print('Verified original binary download: ' + name, flush=True)
    return target

package = download(655579247, 'KayuLocalAssistant-linux-arm64.tar.gz', PACKAGE_SHA)
delta = download(int(os.environ['KIKO_BASELINE_ASSET']), 'original15-delta.zip', DELTA_SHA)
candidate = root / 'candidate'; candidate.mkdir()
with tarfile.open(package, 'r:gz') as archive:
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts and path.parts[0] == 'KayuLocalAssistant'
        assert member.isfile() or member.isdir()
    archive.extractall(candidate, filter='data')
candidate = candidate / 'KayuLocalAssistant'
assert digest(candidate / 'KayuLocalAssistant') == EXE_SHA

# Import only the updater/control code actually embedded in this candidate.
# Third-party QA dependencies come from the standard runner, not private sources.
pyz = CArchiveReader(str(candidate / 'KayuLocalAssistant')).open_embedded_archive('PYZ.pyz')
class FrozenAppImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != 'app' and not fullname.startswith('app.'): return None
        if fullname not in pyz.toc: raise ImportError('Missing actual frozen module: ' + fullname)
        return importlib.util.spec_from_loader(fullname, self, is_package=pyz.toc[fullname][0] in (1, 3))
    def create_module(self, spec): return None
    def exec_module(self, module):
        module.__file__ = str(candidate / 'KayuLocalAssistant') + '::' + module.__name__
        code = pyz.extract(module.__name__)
        if code is not None: exec(code, module.__dict__)
sys.meta_path.insert(0, FrozenAppImporter())
from app.desktop.update_receipt import UpdateReceiptStore
from app.desktop.update_worker import (NativeUpdateOperations, WorkerTicket, installed_version,
    prepare_worker, launch_worker, tree_fingerprint)
from app.desktop.update_lifecycle import ParticipantRecord, UpdateCoordinator, process_identity
from app.desktop.updater import DesktopUpdateAsset

work = root / 'fixture'; work.mkdir()
program = work / 'program/KayuLocalAssistant'; program.mkdir(parents=True)
with zipfile.ZipFile(delta) as archive:
    manifest = json.loads(archive.read('baseline-manifest.json'))
    assert manifest['oldVersion'] == '0.3.15' and manifest['newSourceCommit'] == HEAD
    assert manifest['oldArchiveSha256'] == 'fe67683caf5f74f33534f8f4a0937169ea06060561f2c4a26f2e314fd563ac6d'
    for name in manifest['directories']:
        assert not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
        (program / name).mkdir(parents=True, exist_ok=True)
    for name, info in manifest['files'].items():
        assert not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
        target = program / name; target.parent.mkdir(parents=True, exist_ok=True)
        if name in manifest['changedFiles']:
            with archive.open('delta/' + name) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
            target.chmod(info['mode'])
        else:
            source = candidate / name
            assert source.is_file() and not source.is_symlink() and digest(source) == info['sha256']
            if source.stat().st_mode & 0o777 == info['mode']:
                os.link(source, target)
            else:
                shutil.copyfile(source, target); target.chmod(info['mode'])
        assert target.stat().st_size == info['bytes'] and digest(target) == info['sha256']
    assert {p.relative_to(program).as_posix() for p in program.rglob('*') if p.is_file()} == set(manifest['files'])
exe = program / 'KayuLocalAssistant'
assert installed_version(program, 'linux-arm64') == '0.3.15'
libraries = [program/'_internal/libQt6WebEngineCore.so.6',
    program/'_internal/PySide6/Qt/plugins/platforms/libqxcb.so']
link_audit=[]
for library in libraries:
    assert library.is_file(), 'Required real Qt dependency target absent'
    result=subprocess.run(['ldd',str(library)],env={**os.environ,'LD_LIBRARY_PATH':str(program/'_internal')},
        capture_output=True,text=True,timeout=20)
    missing=[line.strip() for line in result.stdout.splitlines() if 'not found' in line]
    link_audit.append(dict(library=library.relative_to(program).as_posix(),exitCode=result.returncode,missing=missing))
    (evidence/'native-linker-preflight.json').write_text(json.dumps(link_audit,indent=2))
    assert result.returncode==0 and not missing, 'Native runner system-library preflight failed before product start'
data = work / 'data'; (data / 'database').mkdir(parents=True); (data / 'files').mkdir()
home = work / 'home'; home.mkdir()
os.environ.update(HOME=str(home), KAYU_LOCAL_DATA_DIR=str(data), OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
original = data / 'files/synthetic-update-original.txt'; original.write_bytes(b'Synthetic original; preserve exactly.\n')
settings = data / 'synthetic-settings.json'; settings.write_bytes(b'{"synthetic":"preserve"}\n')
with sqlite3.connect(data / 'database/shunao.db') as db:
    db.execute('CREATE TABLE kiko_upgrade_fixture(id INTEGER PRIMARY KEY,value TEXT NOT NULL)')
    db.execute('INSERT INTO kiko_upgrade_fixture VALUES(1,?)', ('preserve-real-arm-native',)); db.commit()
store = UpdateReceiptStore(data)
state = dict(sourceCommit=HEAD, version='0.3.16', platform='linux-arm64', complete=False,
    execution='native-aarch64-standard-public-runner', physicalDeviceAcceptance=False,
    modelCalls=0, physicalGuiInput=False, privateProductSourceUploaded=False,
    actualHardware=dict(physicalCores=psutil.cpu_count(logical=False), memoryBytes=psutil.virtual_memory().total),
    exactOriginal15FileCount=len(manifest['files']), original15ExecutableSha256=digest(exe), phases=[])

def record(phase, **values):
    assert not resource_stop.is_set(), 'Owned native fixture stopped by measured runtime guard'
    state['phases'].append(dict(phase=phase, atUtc=datetime.now(timezone.utc).isoformat(), **values))
    (evidence / 'progress.json').write_text(json.dumps(state, indent=2))
    print(phase, flush=True)

x = c.CDLL('libX11.so.6')
x.XOpenDisplay.argtypes=[c.c_char_p]; x.XOpenDisplay.restype=c.c_void_p
x.XDefaultRootWindow.argtypes=[c.c_void_p]; x.XDefaultRootWindow.restype=c.c_ulong
x.XInternAtom.argtypes=[c.c_void_p,c.c_char_p,c.c_int]; x.XInternAtom.restype=c.c_ulong
x.XQueryTree.argtypes=[c.c_void_p,c.c_ulong,c.POINTER(c.c_ulong),c.POINTER(c.c_ulong),c.POINTER(c.POINTER(c.c_ulong)),c.POINTER(c.c_uint)]
x.XFree.argtypes=[c.c_void_p]
x.XGetWindowProperty.argtypes=[c.c_void_p,c.c_ulong,c.c_ulong,c.c_long,c.c_long,c.c_int,c.c_ulong,c.POINTER(c.c_ulong),c.POINTER(c.c_int),c.POINTER(c.c_ulong),c.POINTER(c.c_ulong),c.POINTER(c.POINTER(c.c_ubyte))]
class XErrorEvent(c.Structure):
    _fields_=[('type',c.c_int),('display',c.c_void_p),('resourceid',c.c_ulong),('serial',c.c_ulong),
        ('error_code',c.c_ubyte),('request_code',c.c_ubyte),('minor_code',c.c_ubyte)]
def ignorable_x11_error(error_code,request_code):
    return error_code==3 and request_code==20  # Destroyed temporary window during GetProperty only.
x11_errors=[]
def on_x11_error(display,event):
    row=event.contents
    x11_errors.append(dict(errorCode=int(row.error_code),requestCode=int(row.request_code),resource=int(row.resourceid)))
    return 0  # Surface non-transient errors as controlled Python failures below, never success.
x11_error_handler=c.CFUNCTYPE(c.c_int,c.c_void_p,c.POINTER(XErrorEvent))(on_x11_error)
x.XSetErrorHandler.argtypes=[type(x11_error_handler)];x.XSetErrorHandler.restype=c.c_void_p
x.XSetErrorHandler(x11_error_handler)
def check_x11_errors():
    (evidence/'x11-observer-events.json').write_text(json.dumps(x11_errors[-100:],indent=2))
    assert all(ignorable_x11_error(row['errorCode'],row['requestCode']) for row in x11_errors), 'Unexpected native X11 query error'
display=x.XOpenDisplay(None); assert display
top=x.XDefaultRootWindow(display); pid_atom=x.XInternAtom(display,b'_NET_WM_PID',0)
def windows(pid):
    r,p=c.c_ulong(),c.c_ulong(); children=c.POINTER(c.c_ulong)(); count=c.c_uint()
    assert x.XQueryTree(display,top,c.byref(r),c.byref(p),c.byref(children),c.byref(count))
    check_x11_errors()
    found=[]
    try:
        for index in range(count.value):
            window=children[index]; kind=c.c_ulong(); fmt=c.c_int(); n=c.c_ulong(); remaining=c.c_ulong(); body=c.POINTER(c.c_ubyte)()
            result=x.XGetWindowProperty(display,window,pid_atom,0,1,0,0,c.byref(kind),c.byref(fmt),c.byref(n),c.byref(remaining),c.byref(body))
            check_x11_errors()
            try:
                if result==0 and fmt.value==32 and n.value==1 and body and c.cast(body,c.POINTER(c.c_ulong))[0]==pid: found.append(window)
            finally:
                if body: x.XFree(body)
    finally:
        if children: x.XFree(children)
    return found

def observe(version, timeout=100):
    deadline=time.monotonic()+timeout
    with httpx.Client(trust_env=False,timeout=1) as client:
        while time.monotonic()<deadline:
            for process in psutil.process_iter(['exe'],ad_value=None):
                try:
                    if process.info['exe']!=str(exe) or not process.is_running() or process.status()==psutil.STATUS_ZOMBIE: continue
                    assert process.username()==psutil.Process().username()
                    native=windows(process.pid)
                    if not native or not any(row.status=='LISTEN' and row.laddr.port==8765 for row in process.net_connections('tcp')): continue
                    status=client.get('http://127.0.0.1:8765/local-assistant/v1/status').json()
                    if status.get('state')!='ready' or status.get('contentOperationsEnabled') is not True: continue
                    identity=process_identity(process); participants=[]
                    for path in (store._root/'participants').glob('*.json'):
                        row=ParticipantRecord.model_validate(store._read(path))
                        if row.identity==identity and row.role=='window' and row.idle is True and 0<=time.time()-row.updated_at<=2:
                            participants.append(row.model_dump(by_alias=True))
                    if participants:
                        assert installed_version(program,'linux-arm64')==version
                        return dict(version=version,identity=identity.model_dump(by_alias=True),nativeWindows=native,
                            ownListener=True,freshActualSignedFrontendIdle=participants,executableSha256=digest(exe))
                except (psutil.NoSuchProcess,psutil.AccessDenied,httpx.HTTPError,ValueError): continue
            time.sleep(.2)
    raise RuntimeError('Actual exact process/window/listener/frontend idle did not pass')

def protection():
    with closing(sqlite3.connect((data/'database/shunao.db').as_uri()+'?mode=ro',uri=True)) as db:
        result={}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            if name not in ('kiko_upgrade_fixture','app_users','categories','materials','material_sources','content_units','memories') and not name.startswith(('local_knowledge','local_memory','local_conversation','account','subscription')): continue
            quoted='"'+name.replace('"','""')+'"'; columns=[row[1] for row in db.execute('PRAGMA table_info('+quoted+')')]
            stable=[i for i,col in enumerate(columns) if not (name in ('app_users','categories') and col=='updated_at')]
            result[name]=sorted(sha256(repr(tuple(row[i] for i in stable)).encode()).hexdigest() for row in db.execute('SELECT * FROM '+quoted))
    return dict(tables=result,originalSha256=digest(original),settingsSha256=digest(settings))

asset=DesktopUpdateAsset(fileName=package.name,url='https://github.com/liudingshu/liudingshu.github.io/releases/download/desktop-v0.3.16/'+package.name,
    sha256=PACKAGE_SHA,byteSize=package.stat().st_size,installerKind='linux-tar')
download_path=store._root/'downloads/0.3.16'/package.name; download_path.parent.mkdir(parents=True)
os.link(package,download_path)
def prepare():
    run=store.begin('0.3.15','0.3.16','linux-arm64',PACKAGE_SHA)
    prepared=prepare_worker(data,run,download_path,asset,executable=exe)
    ticket=WorkerTicket.model_validate(store._read(prepared.ticket_path))
    return run,prepared,NativeUpdateOperations(ticket,store)

try:
    with (evidence/'old.stdout').open('xb') as out,(evidence/'old.stderr').open('xb') as err:
        subprocess.Popen([str(exe)],cwd=program,stdout=out,stderr=err,close_fds=True)
    record('actual-original15-native-window-idle',observation=observe('0.3.15'))
    before=protection(); old_tree=tree_fingerprint(program)[0]
    record('actual-original15-full-runtime-and-data-baseline',protection=before,treeSha256=old_tree)
    run,prepared,ops=prepare()
    with store._locked('worker.lock'):
        store.advance(run.run_id,'quiescing')
        coordinator=UpdateCoordinator(data,exe); participants=coordinator.request_shutdown(run.run_id)
        coordinator.wait_for_exit(participants,before_exit=ops.snapshot)
        store.advance(run.run_id,'installing'); code=ops.install(); assert code==0
        store.advance(run.run_id,'verifying',installer_exit_code=code)
        proof=ops.verify_new(); assert proof.version=='0.3.16' and digest(exe)==EXE_SHA
        record('actual16-installer-native-boot-before-injected-fault',bootProof=proof.model_dump(by_alias=True))
        store.advance(run.run_id,'failed',error_code='DESKTOP_UPDATE_INTERRUPTED')
        old_proof=ops.recover(); assert old_proof.version=='0.3.15'
        assert tree_fingerprint(program)[0]==old_tree
        rolled=store.advance(run.run_id,'rolledBack',boot_version=old_proof.version,boot_id=old_proof.boot_id)
        observation=observe('0.3.15'); assert protection()==before
        record('actual15-full-program-data-recovery-native-window',receipt=rolled.model_dump(by_alias=True),
            bootProof=old_proof.model_dump(by_alias=True),observation=observation)
    run,prepared,ops=prepare(); launch_worker(prepared,data)
    record('actual-original15-frozen-update-worker-dispatched',runId=run.run_id)
    deadline=time.monotonic()+500
    while time.monotonic()<deadline:
        completed=store.load(); assert completed.run_id==run.run_id
        if completed.stage in ('completed','rolledBack'): break
        time.sleep(.25)
    assert completed.stage=='completed',completed.model_dump(by_alias=True)
    observation=observe('0.3.16'); assert protection()==before and digest(exe)==EXE_SHA
    state.update(complete=True,actualInstallerReceipt=completed.model_dump(by_alias=True),
        actualReopenedNewest=observation,protectionBefore=before,protectionAfter=protection(),
        auditedVolatileColumnsExcluded=['app_users.updated_at','categories.updated_at'])
    record('native-arm64-upgrade-recovery-newest-reopen-accepted')
    (evidence/'acceptance-linux-arm64.json').write_text(json.dumps(state,indent=2))
except BaseException as error:
    state['failure'] = dict(errorClass=type(error).__name__,fixedError=getattr(error,'code',None),resourceStop=resource_stop.is_set())
    (evidence/'failed.json').write_text(json.dumps(state,indent=2))
    raise
