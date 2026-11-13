"""Block credentials, local databases/caches, and secrets in Git changes."""
import os,re,shutil,subprocess,sys
from pathlib import Path

def git(*args):
    return subprocess.check_output(['git',*args]).decode('utf-8',errors='replace').strip()

def git_paths(*args):
    data=subprocess.check_output(['git',*args])
    return {name.decode('utf-8',errors='surrogateescape') for name in data.split(b'\0') if name}

def forbidden(name):
    p=Path(name); parts=set(p.parts)
    if parts & {'.codex','.ssh','.aws','node_modules','.venv','venv','__pycache__','.pnpm-store','AppData'}:return True
    n=p.name.lower()
    if n in {'.env.example','.env.sample'} or n.endswith('.env.example'):return False
    return bool(re.search(r'(^\.env($|\.)|\.env$|\.(sqlite3?|db|db3|pem|pfx|p12|key)(-|$)|credentials.*\.json$|secrets.*\.json$|^\.dev\.vars$|^\.local-.*\.json$)',n))

def main():
    root=Path(git('rev-parse','--show-toplevel'))
    try: configured=git('config','--get','codex.gitleaksPath')
    except subprocess.CalledProcessError: configured=''
    exe=configured if configured and Path(configured).is_file() else shutil.which('gitleaks')
    if not exe:
        print('Commit blocked: install Gitleaks or set git config codex.gitleaksPath to its executable.');return 2
    config=root/'.repo-security/gitleaks.toml'
    if '--pre-push' in sys.argv:
        ranges=[];shas=[]
        for line in sys.stdin:
            fields=line.split()
            if len(fields)!=4 or fields[1]=='0'*40:continue
            local,remote=fields[1],fields[3];shas.append(local)
            ranges.append(local if remote=='0'*40 else remote+'..'+local)
        if not ranges:return 0
        names=set()
        for sha in shas:names.update(git_paths('ls-tree','-r','--name-only','-z',sha))
        args=['git','--log-opts',' '.join(ranges)]
    else:
        names=git_paths('diff','--cached','--name-only','--diff-filter=ACMR','-z')
        args=['git','--pre-commit','--staged']
    bad=sorted(n for n in names if forbidden(n))
    if bad:
        print('Blocked local credentials/databases/caches: '+', '.join(bad[:8]));return 1
    if '--pre-push' not in sys.argv:
        oversized=[n for n in names if int(git('cat-file','-s',':'+n))>25*1024*1024]
        if oversized:
            print('Commit blocked: files exceed 25 MiB: '+', '.join(oversized[:5]));return 1
    return subprocess.run([exe,*args,'--config',str(config),'--redact=100','--no-banner','--no-color','--log-level','error',str(root)]).returncode

if __name__=='__main__':raise SystemExit(main())
