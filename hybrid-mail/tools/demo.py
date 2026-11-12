#!/usr/bin/env python3
"""Exercise separate sender/proxy/receiver processes with a MIME attachment."""
import argparse, email.policy, email.parser, hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile
from email.message import EmailMessage

PROJECT=pathlib.Path(__file__).resolve().parents[1]
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=pathlib.Path);args=ap.parse_args()
    subprocess.run([sys.executable,str(PROJECT/'tools/go.py'),'build','-o',str(PROJECT/'bin/hybrid-mail'),'./cmd/hybrid-mail'],check=True)
    runs=PROJECT/'runs';runs.mkdir(exist_ok=True)
    dest=args.out.resolve() if args.out else pathlib.Path(tempfile.mkdtemp(prefix='demo-',dir=runs))
    if args.out: dest.mkdir(mode=0o700)
    binary=PROJECT/'bin/hybrid-mail'; results={}
    attachment=bytes(range(256))*64
    msg=EmailMessage(policy=email.policy.SMTP)
    msg['From']='Alice <alice@example.test>';msg['To']='Bob <bob@example.test>'
    msg['Subject']='Hybrid forwarding: MIME body and attachment'
    msg['Date']='Mon, 09 Nov 2026 10:00:00 +1100';msg['Message-ID']='<demo-001@example.test>'
    msg.set_content('Hello Bob and Carol,\nThis is a hybrid encrypted forwarding demonstration.\n附件保持不变。\n')
    msg.add_attachment(attachment,maintype='application',subtype='octet-stream',filename='example.bin')
    msg.set_boundary('latpre-hybrid-demo-boundary-20261109');plain=msg.as_bytes()
    for mode in ('classical','hybrid'):
        folder=dest/mode;folder.mkdir(mode=0o700)
        for role in ('sender','proxy','receiver'): (folder/role).mkdir(mode=0o700)
        commands=[]
        def invoke(role,*arguments):
            commands.append({'role':role,'args':list(arguments)})
            return subprocess.run([str(binary),*arguments],cwd=folder/role,check=True,text=True,capture_output=True).stdout
        # Bob performs setup and creates both dedicated forwarding key pairs.
        invoke('.', 'init','-mode',mode,'-out','bob')
        invoke('.', 'authorize','-key','bob/bob-secret.json','-out','handoff')
        shutil.copyfile(folder/'bob/bob-public.json',folder/'sender/public.json')
        shutil.move(folder/'handoff/proxy.bin',folder/'proxy/authorization.bin')
        shutil.move(folder/'handoff/carol-secret.json',folder/'receiver/key.json')
        os.chmod(folder/'proxy/authorization.bin',0o600);os.chmod(folder/'receiver/key.json',0o600)
        (folder/'sender/message.eml').write_bytes(plain)
        invoke('sender','send','-public','public.json','-in','message.eml','-out','source.bin')
        invoke('.', 'open-source','-key','bob/bob-secret.json','-in','sender/source.bin','-out','bob/recovered.eml')
        assert (folder/'bob/recovered.eml').read_bytes()==plain
        # Remove only this demo's disposable Bob secret before proxy execution.
        (folder/'bob/bob-secret.json').unlink()
        shutil.copyfile(folder/'sender/source.bin',folder/'proxy/source.bin')
        invoke('proxy','forward','-auth','authorization.bin','-in','source.bin','-out','forwarded.bin')
        shutil.copyfile(folder/'proxy/forwarded.bin',folder/'receiver/forwarded.bin')
        invoke('receiver','open-receiver','-key','key.json','-in','forwarded.bin','-out','recovered.eml')
        recovered=(folder/'receiver/recovered.eml').read_bytes();assert recovered==plain
        parsed=email.parser.BytesParser(policy=email.policy.default).parsebytes(recovered)
        parts=list(parsed.iter_attachments());assert len(parts)==1 and parts[0].get_payload(decode=True)==attachment
        source_info=json.loads(invoke('sender','inspect','-in','source.bin'))
        target_info=json.loads(invoke('receiver','inspect','-in','forwarded.bin'))
        def body(path):
            b=path.read_bytes();return b[134+int.from_bytes(b[118:122],'big')+int.from_bytes(b[122:126],'big'):]
        assert body(folder/'sender/source.bin')==body(folder/'receiver/forwarded.bin')
        results[mode]={'passed':True,'bob_secret_removed_before_forwarding':True,'independent_processes':True,'mime_bytes':len(plain),'attachment_bytes':len(attachment),'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'source':source_info,'forwarded':target_info,'commands':commands}
    (dest/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps({'output':str(dest),'classical':'PASS','hybrid_light':'PASS','mime_bytes':len(plain),'attachment_bytes':len(attachment)},indent=2))
if __name__=='__main__':main()
