#!/usr/bin/env python3
"""Build firmware-only alpha artifacts and their integrity manifest. No USB access."""
import sys
sys.dont_write_bytecode = True
import hashlib
import json
from pathlib import Path
import subprocess
from check_update import check_image

root=Path(__file__).resolve().parents[1]
out=root.parent/'website-final/public/firmware'
out.mkdir(parents=True,exist_ok=True)
manifest={}
for size in (4,16):
    for setup in (False,True):
        name=f'{size}mb'+('-setup' if setup else '')
        target=f'target/{"setup-" if setup else ""}{size}mb'
        features=','.join((['flash-16mb'] if size==16 else [])+(['otp-provisioning'] if setup else []))
        command=['cargo','build','--locked','--release','--target-dir',target]
        if features:command+=['--features',features]
        subprocess.run(command,cwd=root,check=True)
        elf=root/target/'thumbv8m.main-none-eabihf/release/firmware'
        details=check_image(elf.read_bytes(),size,allow_provisioning=setup)
        file=out/f'doohickey-{name}.uf2'
        subprocess.run(['picotool','uf2','convert',str(elf),'-t','elf',str(file),'--family','rp2350-arm-s'],check=True,cwd=root)
        manifest[name]={'version':details['version'],'flash_bytes':size*1024*1024,'otp_provisioning':setup,'secure_boot':False,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
