"""Update only unchanged built-in predicates; preserve analyst customization."""
import ast,json,sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
old={
'R01':{'source':'windows.security','event_id':['1102']},
'R02':{'event_id':['104'],'source':['windows.system','windows.application']},
'R03':{'source':'windows.security','event_id':['4720']},
'R05':{'event_id':['7045','4697']},
'R06':{'source':'windows.security','event_id':['4698']},
'R07':{'source':'windows.security','event_id':['4719']},
'R13':{'source':'windows.security','event_id':['4740']},
'R16':{'source':'windows.security','event_id':['4625']},
'R21':{'source':'windows.security','event_id':['4624'],'extra':{'LogonType':['10']},'src_ip_public':True}}
tree=ast.parse((ROOT/'soc_server/app/seed.py').read_text(encoding='utf-8'))
spec=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DEFAULT_RULES' for t in n.targets))
new={row[0]:row[4] for row in spec}
conn=sqlite3.connect(ROOT/'soc_server/instance/soc.db',timeout=30)
backup=ROOT/'docs/kiem_thu_toan_bo_SOC/private-soc-before-legacy.db'
if not backup.exists():
 b=sqlite3.connect(backup);conn.backup(b);b.close()
report=[]
with conn:
 for code,previous in old.items():
  row=conn.execute('select id,conditions,is_builtin from detection_rules where code=?',(code,)).fetchone()
  if not row:continue
  current=json.loads(row[1]);status='kept_custom'
  if row[2] and current==previous:
   conn.execute('update detection_rules set conditions=? where id=?',(json.dumps(new[code],ensure_ascii=False),row[0]));status='updated'
  elif current==new[code]:status='already_updated'
  report.append({'code':code,'status':status,'before':current,'after':new[code] if status!='kept_custom' else current})
(ROOT/'docs/kiem_thu_toan_bo_SOC/legacy-rule-migration.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({x['code']:x['status'] for x in report},ensure_ascii=False))
