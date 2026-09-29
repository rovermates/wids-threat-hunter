"""Extract publisher labels without using spreadsheet-rounded feature values."""
from pathlib import Path
import zipfile,xml.etree.ElementTree as E,csv
p=Path('data/raw/wpa3/RogueAP.xlsx');z=zipfile.ZipFile(p);ns='{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
strings=[''.join(t.itertext()) for t in E.fromstring(z.read('xl/sharedStrings.xml'))]
with z.open('xl/worksheets/sheet1.xml') as source,open('data/raw/wpa3/RogueAP-labels.csv','w',newline='') as output:
 writer=csv.writer(output);writer.writerow(['frame.number','frame.len','Label']);count=0
 for _,row in E.iterparse(source,events=['end']):
  if row.tag!=ns+'row':continue
  if row.get('r')=='1':row.clear();continue
  vals={}
  for c in row:
   col=c.get('r').rstrip('0123456789')
   if col in ['B','C','EX']:
    v=c.find(ns+'v');v=v.text if v is not None else '';vals[col]=strings[int(v)] if c.get('t')=='s' else v
  writer.writerow([vals['B'],vals['C'],vals['EX']]);count+=1;row.clear()
  if count%100000==0:print(count,flush=True)
print('Label rows',count)
