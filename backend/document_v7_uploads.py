"""Record verified final-model upload counts alongside historical PCAP instructions."""
import json
from pathlib import Path

def run():
    folder=Path('data/dashboard-round2-heldout')
    results=json.loads((folder/'final-v7-upload-results.json').read_text())
    assert len(results)==5 and all(r['repeat_matches'] for r in results)
    lines=['# Current default: final v7','',
        'Run `start.cmd` from the project root and open http://127.0.0.1:8000.',
        'Upload these PCAPs one at a time; label CSV sidecars are not upload inputs.',
        'All five files were tested twice through the actual API; every repeated packet-result digest matched.','',
        '| File | Processed | Evaluated advertisements | Flagged | Suspected APs |',
        '|---|---:|---:|---:|---:|']
    for result in results:
        c=result['runs'][0]['capture']
        lines.append(f"| {result['file']} | {c['total_packets']} | {c['evaluated_packets']} | {c['flagged_packets']} | {c['detected_rogue_aps']} |")
    lines += ['', 'Normal-period alerts remain false-alert checks, not evidence of verified rogue identities.',
        'Final v7 improved one missed advertisement in the complete RogueAP regression; false-alert counts did not improve.',
        'The comparisons below are historical v6/original-v7 results, not the new default. Original v7 remains available through `start-experimental-v7.cmd` on port 8001.',
        '', '---', '']
    readme=folder/'README.md';old=readme.read_text(encoding='utf8')
    if old.startswith('# Current default: final v7'):
        old=old.split('\n---\n',1)[1].lstrip()
    readme.write_text('\n'.join(lines)+old,encoding='utf8')
    report=Path('docs/refined-v7-results.md')
    report.write_text(report.read_text(encoding='utf8')+'\n## Software verification\n\n'
        'The 105-test backend suite and the added confirmation-boundary test passed (106 distinct tests). '
        'The frontend production build succeeded. All five browser scenarios passed. '
        'All five packaged PCAPs completed twice through the upload API, with matching prediction digests. '
        'See `data/dashboard-round2-heldout/final-v7-upload-results.json` for exact counts and artifact hashes.\n',encoding='utf8')

if __name__=='__main__':run()
