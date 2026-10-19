"""Observe the free verification host without product source, packages or credentials."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

system = platform.system()
if system == 'Linux':
    physical = set()
    for entry in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/topology'):
        physical.add(((entry / 'physical_package_id').read_text().strip(), (entry / 'core_id').read_text().strip()))
    cores = len(physical)
    values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    memory = int(values['MemTotal'].split()[0]) * 1024
elif system == 'Darwin':
    cores = int(subprocess.check_output(['sysctl', '-n', 'hw.physicalcpu'], text=True).strip())
    memory = int(subprocess.check_output(['sysctl', '-n', 'hw.memsize'], text=True).strip())
elif system == 'Windows':
    raw = subprocess.check_output(['powershell', '-NoProfile', '-Command',
        '$c=Get-CimInstance Win32_ComputerSystem; $p=Get-CimInstance Win32_Processor; '
        '@{memory=[long]$c.TotalPhysicalMemory;cores=($p|Measure-Object NumberOfCores -Sum).Sum}|ConvertTo-Json -Compress'], text=True)
    host = json.loads(raw)
    cores, memory = int(host['cores']), int(host['memory'])
else:
    raise RuntimeError('Unexpected standard runner operating system')
record = dict(target=os.environ['KIKO_QA_TARGET'], runner=os.environ['KIKO_QA_RUNNER'],
              observedEpoch=time.time(), system=system, processMachine=platform.machine(),
              logicalCpuCount=os.cpu_count(), physicalCpuCores=cores, totalMemoryBytes=memory,
              freeDiskBytes=shutil.disk_usage(Path.cwd()).free,
              productCpuAndMemoryMinimumMet=cores >= 4 and memory >= 8 * 1024**3,
              sourceOrUserDataDownloaded=False, buildOrProductAcceptancePerformed=False,
              standardPublicRunnerOnly=True, billingChanged=False)
print('KIKO_HOST_OBSERVATION=' + json.dumps(record, sort_keys=True), flush=True)
