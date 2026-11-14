import json
from pathlib import Path
import runpy
import xml.etree.ElementTree as ET


def test_custom_rules_are_parseable_and_do_not_consume_ground_truth():
    root = ET.parse('siem/healthcare_rules.xml').getroot()
    ids = [int(item.attrib['id']) for item in root.findall('rule')]
    assert len(ids) == len(set(ids)) and all(100000 <= identity <= 120000 for identity in ids)
    assert {110101, 110102, 110103, 110201, 110301, 110302} <= set(ids)
    assert not {'action', 'run_id', 'scenario', 'is_attack'} & {item.attrib['name'] for item in root.iter('field')}
    for rule_id, action in zip(range(110001, 110005), ('login_failure', 'record_read', 'document_update', 'export_completed')):
        classifier = root.find(f"rule[@id='{rule_id}']/action[@type='osregex']")
        assert classifier is not None and classifier.text == f'^{action}$'
    for base in [110001, 110002, 110003, 110004]:
        assert int(root.find(f"rule[@id='{base}']").attrib['level']) >= 1


def test_dashboard_has_eight_panels_and_resolvable_references():
    objects = [json.loads(line) for line in Path('siem/dashboard.ndjson').read_text().splitlines()]
    registry = {(obj['type'], obj['id']) for obj in objects}
    for obj in objects:
        for reference in obj.get('references', []):
            assert (reference['type'], reference['id']) in registry
    dashboard = next(obj for obj in objects if obj['type'] == 'dashboard')
    assert len(json.loads(dashboard['attributes']['panelsJSON'])) == 8
    health = next(obj for obj in objects if obj['id'] == 'healthcare-health')
    assert 'unknown' in health['attributes']['title'] and '90 seconds' in health['attributes']['title']
    state = json.loads(health['attributes']['visState'])
    assert state['type'] == 'vega'
    spec = json.loads(state['params']['spec'])
    assert any('timer' in str(signal) for signal in spec['signals'])
    assert 'data.event_time' in str(spec) and '90000' in str(spec)


def test_dashboard_generator_preserves_verified_wazuh_import_and_refresh_contract():
    generated = runpy.run_path('scripts/build-dashboard.py')['objects']()
    saved = [json.loads(line) for line in Path('siem/dashboard.ndjson').read_text().splitlines()]
    assert generated == saved, 'Regenerate siem/dashboard.ndjson after changing its generator'
    dashboard = next(obj for obj in generated if obj['type'] == 'dashboard')
    attrs = dashboard['attributes']
    panels = json.loads(attrs['panelsJSON'])
    # Missing panel versions crashed the Wazuh 4.14.10 is640To720Panel migration.
    assert all(panel.get('version') == '7.10.0' for panel in panels)
    assert attrs['timeRestore'] is True
    assert (attrs['timeFrom'], attrs['timeTo']) == ('now-4h', 'now')
    assert attrs['refreshInterval'] == {'pause': False, 'value': 10000}
    health = next(obj for obj in generated if obj['id'] == 'healthcare-health')
    spec = json.loads(json.loads(health['attributes']['visState'])['params']['spec'])
    # Explicit autosizing prevents the observed overlapping health banner.
    assert spec.get('autosize') == 'none'
    latest = next(item for item in spec['data'] if item['name'] == 'latest')
    assert latest['url']['body']['size'] == 1
    assert latest['url']['body']['sort'] == [{'timestamp': 'desc'}]
    assert latest['url']['body']['query']['bool']['filter'] == [
        {'term': {'data.service': 'hospital-lab'}},
        {'term': {'data.action': 'service_heartbeat'}},
    ]
