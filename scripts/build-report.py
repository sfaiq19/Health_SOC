"""Build the evidence-based report using private local evidence; emits no raw credentials."""
import csv, json
import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

REPO=Path(__file__).resolve().parents[1]
PRIVATE=Path.home()/'HealthcareSOCLab/evidence'
CAMPAIGN=PRIVATE/'measured-20261113'
OUT=REPO/'report'
OUT.mkdir(exist_ok=True)
ASSETS=OUT/'assets'
ASSETS.mkdir(exist_ok=True)
runs=[]
for folder in sorted(CAMPAIGN.glob('[0-9][0-9]-*')):
    if not (folder/'manifest.json').exists(): continue
    m=json.loads((folder/'manifest.json').read_text())
    metrics=json.loads((folder/'metrics.json').read_text()) if (folder/'metrics.json').exists() else {}
    obs=json.loads((folder/'observations.json').read_text()) if (folder/'observations.json').exists() else {}
    runs.append(dict(folder=folder,name=folder.name,m=m,x=metrics,o=obs))
proof=json.loads((PRIVATE/'native-rule-proof-20261113T193310Z/native-rule-tests.json').read_text())
assert proof['validation_schema'] == 3 and len(proof['cases']) == 26
assert proof['success'] is True and all(case['passed'] is True for case in proof['cases'])
q=json.loads((CAMPAIGN/'query-results/reconciliation-summary.json').read_text())
doc=Document()
sec=doc.sections[0]
sec.page_width=Inches(8.5);sec.page_height=Inches(11)
sec.top_margin=sec.bottom_margin=Inches(.7)
sec.left_margin=sec.right_margin=Inches(.75)
for name in ['Normal','Title','Subtitle','Heading 1','Heading 2','Heading 3']:
    st=doc.styles[name];st.font.name='Calibri';st.font.color.rgb=RGBColor(0,0,0)
doc.styles['Normal'].font.size=Pt(11)
doc.styles['Normal'].paragraph_format.space_after=Pt(7)
doc.styles['Normal'].paragraph_format.line_spacing=1.08
doc.styles['Title'].font.size=Pt(30)
doc.styles['Heading 1'].font.size=Pt(21)
doc.styles['Heading 2'].font.size=Pt(14)
for style in doc.styles:
    for border in list(style.element.iter(qn('w:pBdr'))):
        border.getparent().remove(border)
for name in ['Heading 1','Heading 2','Heading 3']:
    doc.styles[name].paragraph_format.keep_with_next=True
header=sec.header.paragraphs[0];header.text='HEALTHCARE SOC  /  ENGINEERING REPORT'
header.runs[0].font.size=Pt(9)
footer=sec.footer.paragraphs[0];footer.text='Synthetic lab • Evidence captured 13–14 November 2026 UTC    |    '
field=OxmlElement('w:fldSimple');field.set(qn('w:instr'),'PAGE');footer._p.append(field)
def para(s,style=None): return doc.add_paragraph(s,style)
def title(s):doc.add_heading(s,0)
def heading(s):doc.add_heading(s,2)
def page(s):doc.add_page_break();doc.add_heading(s,1)
def table(headers,rows,widths=None):
    t=doc.add_table(rows=1, cols=len(headers))
    t.autofit=False
    if widths:
        for column, width in zip(t.columns, widths):
            column.width=Inches(width)
    for i,h in enumerate(headers): t.rows[0].cells[i].text=str(h)
    for row in rows:
        cells=t.add_row().cells
        for i,val in enumerate(row):cells[i].text=str(val)
    for ri,row in enumerate(t.rows):
        trPr=row._tr.get_or_add_trPr()
        if ri==0:trPr.append(OxmlElement('w:tblHeader'))
        for i,c in enumerate(row.cells):
            if widths:c.width=Inches(widths[i])
            pr=c._tc.get_or_add_tcPr()
            borders=OxmlElement('w:tcBorders')
            for side in ['top','left','bottom','right']:
                e=OxmlElement('w:'+side);e.set(qn('w:val'),'single');e.set(qn('w:sz'),'4');e.set(qn('w:color'),'D9D9D9');borders.append(e)
            pr.append(borders)
            shade=OxmlElement('w:shd');shade.set(qn('w:fill'),'20364D' if ri==0 else ('F1F5F8' if ri%2 else 'FFFFFF'));pr.append(shade)
            mar=OxmlElement('w:tcMar')
            for edge in ['top','left','bottom','right']:
                e=OxmlElement('w:'+edge);e.set(qn('w:w'),'85');e.set(qn('w:type'),'dxa');mar.append(e)
            pr.append(mar)
            for p in c.paragraphs:
                p.paragraph_format.space_after=Pt(2)
                for r in p.runs:
                    r.font.size=Pt(9)
                    if ri==0:r.font.bold=True;r.font.color.rgb=RGBColor(255,255,255)
    para('')
    return t
def cap(s):p=para(s);p.paragraph_format.space_after=Pt(10);p.runs[0].font.size=Pt(9)
def selected(prefix):return [r for r in runs if r['name'].startswith(tuple(prefix))]
def scenario_rows(rs):
    return [(r['name'],r['x'].get('status','control'),str(r['x'].get('source_events','—')),
             ', '.join(r['x'].get('observed_rules',[])) or 'none',
             f"{min(r['x']['alert_latencies_s']):.3f}–{max(r['x']['alert_latencies_s']):.3f}" if r['x'].get('alert_latencies_s') else 'N/A') for r in rs]
def frames(r,limit=4):
    vals=[]
    tshark=Path('C:/Program Files/Wireshark/tshark.exe')
    decoded=subprocess.run([str(tshark), '-r', str(r['folder']/'traffic.pcapng'),
        '-d', 'tcp.port==8080,http', '-d', 'tcp.port==9080,http', '-d', 'tcp.port==9081,http',
        '-Y', 'http.response', '-T', 'fields', '-E', 'separator=,',
        '-e', 'http.request_in', '-e', 'http.response.code', '-e', 'frame.number'],
        capture_output=True, text=True, check=True)
    responses={}
    for line in decoded.stdout.splitlines():
        fields=line.split(',')
        if len(fields)==3 and fields[0]:
            responses[fields[0]]=f'{fields[1]} (frame {fields[2]})'
    with (r['folder']/'frames.csv').open(encoding='utf-8-sig',newline='') as f:
        for row in csv.DictReader(f):
            method=row.get('http.request.method','')
            uri=row.get('http.request.uri','')
            if method and (not vals or (method,uri)!=(vals[-1][1],vals[-1][2])):
                vals.append((row['frame.number'],method,uri,responses.get(row['frame.number'],'Not decoded')))
                if len(vals)>=limit:break
    return vals

# Cover and result overview
title('Healthcare SOC')
para('Implementation, native detection and measured evaluation', 'Subtitle')
para('Technical report • 14 November 2026')
para('A synthetic Windows hospital service and an Ubuntu Wazuh security operations centre were exercised across an isolated VMware host-only network. The campaign includes authentication misuse, rapid dummy-document modification and a controlled synthetic export.')
heading('Observed outcome')
para('The installed Wazuh 4.14.10 engine passed all 26 native rule checks. Fourteen observe-mode bundles recorded complete evaluation results, including three repetitions of each attack. All nine attack runs produced the required detection families. Three ten-minute benign holdouts recorded zero actionable incidents.')
table(['Measure','Observed result'],[
('Native proof','26/26, schema 3, all three expiry controls passed'),
('Attack repetitions','9/9 required detection families observed'),
('S2 file evidence','50/50 native SHA-256 pairs per repetition; seeded restoration recorded'),
('S3 transfer evidence','5,000,000 bytes per repetition, independent object/receipt digest match'),
('Rule processing latency','0.119–1.951 s in Nov 13 campaign (Nov 14 revalidated S2: 0.077–1.913 s)'),
('Task 9 status','Technical report, visual QA, and reproducibility artifacts complete; separate group-member retesting waived')],[2,4.8])
para('Evidence is retained privately under HealthcareSOCLab/evidence. This report cites run directories and opaque run IDs so the reader can trace each result. Original failed and interrupted native attempts remain part of the engineering history.')
para('Scope is limited to fictional records, dummy files and authorized lab receivers. Results describe the controlled campaign and its stated observation windows.')

# Architecture
page('1. Architecture and implemented protocols')
im=Image.new('RGB',(1400,470),'white');draw=ImageDraw.Draw(im)
font=ImageFont.truetype('C:/Windows/Fonts/arial.ttf',27)
small=ImageFont.truetype('C:/Windows/Fonts/arial.ttf',23)
for box,lines in [((25,45,595,385),['WINDOWS HOST  10.77.0.1','Flask / SQLite / 50 dummy files','Wazuh agent 001 • hospital-win','HTTP API on TCP 8080']),((805,45,1375,385),['UBUNTU VM  10.77.0.10','Wazuh manager / indexer / dashboard','Clients + receivers TCP 9080/9081','dumpcap on ens192'])]:
    draw.rounded_rectangle(box,radius=15,outline='#20364D',width=4,fill='#F1F5F8')
    for i,line in enumerate(lines):draw.text((box[0]+20,box[1]+35+i*64),line,font=font if i==0 else small,fill='black')
draw.line((600,180,800,180),fill='#20364D',width=4);draw.polygon([(800,180),(783,170),(783,190)],fill='#20364D')
draw.line((800,255,600,255),fill='#20364D',width=4);draw.polygon([(600,255),(617,245),(617,265)],fill='#20364D')
draw.text((650,110),'VMnet4',font=small,fill='black')
draw.text((170,420),'4 vCPU / 8 GiB RAM / 60 GiB virtual disk • Guest Ubuntu Server 24.04.5',font=small,fill='black')
im.save(ASSETS/'architecture.png');doc.add_picture(str(ASSETS/'architecture.png'),width=Inches(6.9))
cap('Figure 1. Implemented host-only topology. Temporary NAT was disabled for measured traffic.')
table(['Layer / workflow','Implemented interface'],[
('Clinical records','Custom JSON API, 200 fictional patients, role and care-assignment checks'),
('Laboratory','Created order IDs paired one-to-one with subsequent result requests'),
('Devices','Ten simulated identities generating telemetry and heartbeat traffic'),
('Storage and recovery','SQLite transactions, bounded document IDs and seed SHA-256 inventory'),
('Transport','Virtual Ethernet, ARP, IPv4, TCP, HTTP/1.1 on 8080/9080/9081'),
('Monitoring','Authenticated Wazuh endpoint collection, native syscheck, archive indexing and HTTPS dashboard')],[1.7,5.1])
para('The single host-only subnet isolates the exercise. HL7/FHIR, DICOM, production segmentation and clinical safety validation are future integration topics. The custom JSON workflows are the implemented hospital simulation.')
# Methods
page('2. Evidence and evaluation method')
heading('Independent channels')
para('Client manifests provide intended operations and request receipts. Windows app.jsonl records terminal server actions. Wazuh archives establish collected source events, while actionable alerts and native syscheck carry detection and file evidence. PCAPNG and a reproducible tshark CSV establish actual cross-host HTTP traffic. Export receiver receipts and saved binary objects corroborate transfer integrity.')
table(['Gate','Required observation'],[
('Collection','Every unique source event joins its archived event; duplicates counted separately'),
('Detection','Expected family joins source event, request, actor, action/outcome and hospital-win endpoint'),
('S2 attribution','One exact Windows-normalized path and before/after SHA-256 pair across receipt, source, inventory and FIM'),
('S3 integrity','Transfer ID, size and SHA-256 agree between sender, receiver receipt and saved object'),
('Timing','Clock bound ≤1 s; source/receipt/run bounds; ≤30 s rule latency; ≤60 s first index visibility'),
('Capture','Correct interface and cross-host run IDs; measured loss; fresh tshark export matches the supplied CSV'),
('Run separation','Previous manager collection drained, followed by at least 65 seconds of quiet')],[1.35,5.45])
heading('Native proof and repair history')
para('The original 4.14.10 proof passed 23/26 cases. Three wall-clock expiry tests failed and an intervening run ended before final proof creation. The preserved final proof native-rule-proof-20261113T193310Z passes 26/26. Schema 3 waits for engine acknowledgement, retains raw replies and verifies a stable session, independent case sessions, unique inputs and manager-clock gaps above 60 seconds.')
para('Recorded expiry gaps are 65.002 s (authentication), 65.001 s (reads) and 65.001 s (writes). The XML uses native action selectors, retains thresholds 5 and 20 within 60 s, and carries a content-derived loaded revision challenge. Rule child precedence can supersede a parent on the same event.')
para('Packet re-export depends on tshark version. Ubuntu 4.2.2 leaves http.request.uri blank on HTTP response frames, whereas Windows 4.6.9 populates the matched reverse-4-tuple request URI (2,562 response rows across all 18 captures and 52,451 CSV data rows, zero unexpected differences). Strict reverse-4-tuple response-URI equivalence was added and verified under replay-20261114-tshark469 (14/14 observe complete; enforce runs 15–16 and scoped controls 17–18 incomplete under general observe rules for policy/missing-observation gates, 0 packet errors). Pre-compat audit records remain preserved in evidence-verification.json.')

# Baseline
page('3. Stability, baseline and holdouts')
base=[r for r in runs if r['name'][:2] in ['01','02','03','04','05']]
table(['Run','Source / archive','Packets','Visibility s','Clock ms'],[(r['name'],f"{r['x'].get('source_events')}/{r['x'].get('archived_source_events')}",r['x'].get('captured_packets'),r['o'].get('max_index_visibility_delay_s'),r['o'].get('max_clock_offset_ms')) for r in base],[1.7,1.4,1,1.3,1.3])
para('The November 13 15-minute soak used pre/post resource observations, while 30-minute calibration includes 122 samples (available RAM 5055.8–5112.5 MiB, zero swap, max load1 0.268, min disk 31 GiB, 122/122 health OK). On November 14, replacement soak 01-soak-15m-revalidated recorded 760/760 archived/indexed events, 6,574 packets (0 drops), 17 periodic clock samples across the collection window (14 during workload, 9.68–61.42 ms), 17 /proc samples (5,214,276–5,261,976 KiB free RAM, 0 swap, load1 max 0.52, min disk 30.64 GiB, 0 OOM), 1.828–11.943 s ~1 s-loop delays, and three 0.5 s poll-start event_id probes (5.616, 7.985, 5.389 s; query duration unmeasured) after fixing a rollover data.service mapping conflict (01-soak-15m-replacement).')
heading('Benign workload')
para('Calibration produced 1,505 source events with complete archive coverage. It includes 15 order/result pairs and 600 device telemetry events, clinical record activity, bounded document edits and approved exports. Seeds 102, 103 and 104 produced three independent ten-minute holdouts, each with 509 source/archive events.')
para('Zero actionable false incidents were recorded in the three holdouts, giving a defined thirty-minute holdout observation window. The calibration adds thirty benign minutes with zero actionable incidents. The fifteen-minute soak is a separate stability observation.')
heading('Measurement interpretation')
para('In the November 13 campaign, clock bounds (231.7–322.33 ms) were sampled post-run, and soak 01-soak-15m recorded a 1.959 s proxy after tshark exited 139. On November 14, live-revalidation-20261114 recorded periodic /health clocks (19.42–61.42 ms; 14 soak and 3-per-S2 during workload) and OpenSearch event_id polls (1.560–8.400 s poll-start bounds; unmeasured query duration). Prospective helper fixes do not alter preserved JSONs; un-rerun Nov 13 runs retain post-run clocks.')

# Scenario pages
for section,kind,prefix,description,rules,checks,response in [
('4. S1 account misuse','s1',['06','07','08'],'Send six invalid clinician logins over thirty seconds, sign in with the known lab credential, then read thirty distinct off-assignment records over forty-five seconds in observe mode.','110101 ≥5 failures / 60 s; 110102 off-assignment read; 110103 ≥20 successful reads / 60 s.','Each run recorded 39 source/archive events and 31 raw alerts: one 110101, twenty-nine 110102 and one 110103. The burst child superseded a single-read classification on one event.','Inspect the actor, socket address, care assignment, event sequence and actual response content. The enforce rerun produced six 401 responses and thirty 403 blocked reads. Record the denied content and retain legitimate assigned access as the comparison.'),
('5. S2 rapid document changes','s2',['12','13','14'],'Start from the verified fifty-file seed inventory and stable FIM baseline. Pause benign document edits. Perform fifty harmless manifest-listed updates at one per second and retain before/after inventories.','110201 ≥20 successful document updates / 60 s, corroborated by native Windows syscheck rule 550.','November 13 runs recorded 105 source/archive events, two burst alerts and 50/50 matching FIM digests; November 14 repetitions (12..14-s2-revalidated-*) re-verified 105/105 events, 50/50 digests, 0.077–1.913 s alerts, 19.42–57.27 ms clocks, 1.560–8.400 s poll-start bounds (7.707–8.912 s ~1 s-loop max), and five 50/50 restore receipts.','Preserve the attack evidence before resetting. Stop the hospital while restoring the dedicated dummy files, run the bounded restore command with --receipt, verify all fifty seed hashes, restart the service and allow FIM to stabilize. Maintenance belongs outside the attack window.'),
('6. S3 unusual synthetic export','s3',['09','10','11'],'Submit an authenticated 5,000,000-byte synthetic bundle to the registered business-unapproved receiver on Ubuntu port 9080. Preserve sender audit, receiver JSON receipt and the received binary object.','110302 for successful unapproved transfers ≥1,000,000 bytes. 110301 covers the smaller unapproved control.','Each repetition recorded five source/archive events and one 110302 alert. Its independent object and receipt matched the sender size and SHA-256. Three receiver objects total 15,000,000 attack bytes.','Investigate actor, destination policy, transfer ID and digest. The enforce control returned 403 before a completed transfer, with receiver hashes unchanged. Approved 5 MB produced zero custom alerts; unapproved 250 KB produced only 110301.')]:
    page(section);para(description);heading('Detection and evidence');para(rules);para(checks)
    rs=selected(prefix)
    table(['Run','Verdict','Events','Families','Latency s'],scenario_rows(rs),[1,1,0.6,2.1,1.2])
    heading('Representative captured requests')
    table(['Frame','Method','Request target','Response'],frames(rs[0]),[.65,.7,3.7,1.6])
    cap(f"Packet references are from {rs[0]['name']}/frames.csv and traffic.pcapng. Reopen the frame in Wireshark for headers and response association. Authentication material remains private.")
    heading('Analyst response and mitigation');para(response)
    para('The complete run IDs and UTC windows appear in the evidence index. Raw alert counts describe individual records; incident detection is counted once per attempted scenario.')

page('7. Searches, dashboard and collection health')
table(['Query','Observed output'],[
('Q1 activity',f"Calibration {q['Q1_calibration_unique_events']:,} unique events; first S1 run {q['Q1_s1_1_unique_events']}"),
('Q2 authentication',f"{q['Q2_s1_1_auth_hits']} first-S1 auth events: six failures and one successful login"),
('Q3 record access',f"{q['Q3_s1_1_unassigned_reads']} off-assignment reads of {q['Q3_s1_1_distinct_patients']} distinct patients"),
('Q4 native FIM',f"{q['Q4_s2_1_digest_reconciled']}/50 first-S2 file digest pairs reconciled"),
('Q5 export integrity',f"{q['Q5_all_runs_receiver_reconciled']} selected exports; {q['Q5_all_runs_total_bytes']:,.0f} body bytes"),
('Q6 actionable events',f"{q['Q6_campaign_alert_hits']} raw alert documents in the exported query interval, including controls")],[1.4,5.4])
para('Saved JSON/CSV results and reconciliation-summary.json retain query identities. On November 14, live-revalidation-20261114/query-results added explicit UTC range.timestamp bounds (gte 2026-11-13T21:10:24.110Z, lte 2026-11-13T21:13:42.151Z) for Q2_s1_1 (7/7) and Q3_s1_1 (30/30, 30 patients, 0 mismatches) while preserving historical exports. Q5 totals refer to six selected runs with eleven objects. Explicit numeric mappings and keyword pinning for data.service plus 26 hospital string fields are required before indexing.')
doc.add_picture(str(CAMPAIGN/'screenshots/panel-35-fresh.png'),width=Inches(3.5))
doc.add_picture(str(CAMPAIGN/'screenshots/panel-35-stale.png'),width=Inches(3.5))
cap('Figure 2. Archived live heartbeat panel captures, FRESH and STALE. The health view becomes stale beyond ninety seconds. Separate empty/future-clock captures demonstrate UNKNOWN.')
para('The verified import required a 7.10.0 version on dashboard panels and autosize none on the health Vega specification. Refresh is ten seconds over the last four hours. The generator and fresh-install mapping instructions include these compatibility decisions.')
para('Filebeat interruption retained a source event in the local archive and indexed it seven seconds after restart. A manager outage retained an agent-buffered event and delivered it after recovery. The forty-five-second manager observation window retained Active agent status under its configured fifteen-minute disconnection timeout. Windows service-stop testing needs an administrator session.')

page('8. Reproduction, delivery and limitations')
heading('Rebuild sequence')
para('Follow docs/clean-rebuild.md from a clean checkout and dedicated guest. Record package versions, configure the private subnet, seed the runtime, install mappings before indexing, enable archive/FIM collection, install the stamped XML and run all twenty-six native cases. Import the generated dashboard, then perform smoke and reset checks before the full measured campaign.')
heading('Demonstration sequence')
table(['Minutes','Evidence to demonstrate'],[
('0–2','Architecture, roles and normal calibration activity'),
('2–5','S1 request/alert timeline and care enforcement'),
('5–8','S2 independent hashes, FIM and verified restoration'),
('8–10','S3 receiver object integrity and destination enforcement'),
('10–13','Six queries, eight dashboard panels, freshness and recovery'),
('13–15','Per-run results, limitations, clean rebuild and questions')],[.9,5.9])
heading('Reproducibility and submission scope')
para('Clean-environment setup, runtime isolation, and reset steps are documented in docs/clean-rebuild.md, and isolated packaging was checked in a fresh venv via scripts/check-clean-install.py. Separate clean-VM retesting by other group members was waived per project scope decision. Group members may record optional contribution names and demo notes in docs/task9-signoff.md.')
heading('Result boundaries')
para('The lab has one Windows endpoint and one Ubuntu all-in-one SOC. The sample is deterministic and small, uses synthetic HTTP rather than clinical protocols, and observes only the recorded windows. November 14 live revalidation executed a complete replacement 15-minute soak after fixing a UTC rollover data.service conflict, UTC-bounded Q2/Q3 re-exports, three S2 runs, and five 50/50 reset receipts. Saved polling bounds predate response-completion timestamp fixes and exclude query duration; un-rerun November 13 runs retain post-run clocks. Original captures remain private.')
para('Report calculations derive from preserved manifests, raw channels, metrics and query exports. Windows tshark 4.6.9 replay (replay-20261114-tshark469) verifies 14/14 observe runs complete while preserving pre-compatibility audit records in evidence-verification.json. Task 4 interruption/recovery used guest outages; administrator Windows WazuhSvc/15-minute disconnect testing remains disclosed unexecuted scope, and teammate clean-VM retesting was waived.')

page('9. Evidence register and references')
table(['Artifact','Purpose'],[
('native-rule-proof-20261113T193310Z/','Final installed-engine schema-3 proof and 26 hashed transcripts'),
('native-rule-proof-20261113T121654Z/','Historical 23/26 failure retained for repair provenance'),
('native-rule-proof-20261113T191735Z-3b806aa0/','Interrupted attempt retained separately'),
('measured-20261113/01..05','Soak, calibration and three benign holdouts'),
('measured-20261113/06..14','Three repetitions per attack, with objects/inventories and captures'),
('measured-20261113/15..18','Enforcement and approved/small-export controls'),
('replay-20261114-tshark469/','Separate Windows tshark 4.6.9 compatibility replay across all 18 captures'),
('live-revalidation-20261114/','Replacement soak, rollover fix/diagnostics, UTC Q2/Q3, 3x S2, 5x receipts'),
('query-results/ and screenshots/','Actual search exports, reconciliation and live UI evidence'),
('report/evidence-index.md','Exact run IDs, UTC windows, packet references and evidence hashes'),
('docs/clean-rebuild.md','Reference clean setup and reset procedure (teammate retesting waived)')],[3.1,3.7])
heading('Repository references')
para('The binding design is docs/superpowers/specs/2026-10-22-healthcare-soc-design.md. The nine-task specification and 30/30/40 submission matrix are in docs/superpowers/plans/2026-10-22-healthcare-soc.md. Protocols and analyst playbooks are documented in docs/protocols.md and docs/playbooks.md. Current execution results are in docs/implementation-progress.md.')
heading('Authoritative software references')
for text in [
'Wazuh 4.14.10 source, native CLI: https://github.com/wazuh/wazuh/blob/v4.14.10/framework/scripts/wazuh_logtest.py',
'Wazuh 4.14.10 correlation: https://github.com/wazuh/wazuh/blob/v4.14.10/src/analysisd/eventinfo.c',
'Wazuh installation and operating documentation: https://documentation.wazuh.com/current/',
'Ubuntu Server network configuration: https://ubuntu.com/server/docs/explanation/networking/configuring-networks/']:
    para(text)
para('For handover, preserve the private file-hash manifest and a credential-safe evidence copy. Assign contribution ownership using docs/task9-signoff.md and retain reviewer decisions. The report uses no inferred production accuracy or assignment marks.')
doc.save(OUT/'Healthcare_SOC_Report.docx')
print(OUT/'Healthcare_SOC_Report.docx')
