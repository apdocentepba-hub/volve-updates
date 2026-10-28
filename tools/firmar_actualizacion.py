#!/usr/bin/env python3
"""VOLVE release publisher: sign the exact bytes of a HTTPS update manifest.
Run only on a trusted computer; do not commit or distribute the private signing key.
Requires: cryptography package. Use dedicated `volve-updates` GitHub repository.
"""
import argparse, base64, hashlib, json, sys, zipfile
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--private-key',required=True,type=Path)
    p.add_argument('--package',required=True,type=Path,help='zip containing only VOLVE_Centro_Proteccion.exe')
    p.add_argument('--version',required=True)
    p.add_argument('--package-url',required=True)
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    if not args.package_url.startswith('https://') or '@' in args.package_url.split('/')[2]: p.error('package URL must use HTTPS')
    parts=args.version.split('.')
    if len(parts)!=3 or not all(x.isdigit() for x in parts):p.error('version must be x.y.z')
    if tuple(map(int,parts)) <= (0,14,0):p.error('new release must be above 0.14.0')
    with zipfile.ZipFile(args.package) as z:
        if z.namelist()!=['VOLVE_Centro_Proteccion.exe'] :p.error('package must contain only VOLVE_Centro_Proteccion.exe')
    pkg=args.package.read_bytes()
    if not pkg: p.error('empty package')
    m={'product':'VOLVE','channel':'stable','version':args.version,
       'published_at':'',
       'windows_amd64':{'url':args.package_url,'sha256':hashlib.sha256(pkg).hexdigest(),'size':len(pkg)}}
    from datetime import datetime, timezone
    m['published_at']=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    data=(json.dumps(m,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')
    key=load_pem_private_key(args.private_key.read_bytes(),password=None)
    signature=base64.b64encode(key.sign(data)).decode('ascii')+'\n'
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'manifest.json').write_bytes(data)
    (args.out/'manifest.sig').write_text(signature,encoding='ascii')
    print('Signed release manifest',args.version, 'SHA256='+m['windows_amd64']['sha256'])
if __name__=='__main__':main()
