"""Generate candidate OpenSearch saved objects; native import must be verified in Wazuh."""
import json
from pathlib import Path


def text_mark(text, y, size, fill):
    encoding = {'x': {'value': 20}, 'y': {'value': y}, 'fontSize': {'value': size},
                'text': text, 'fill': fill}
    return {'type': 'text', 'encode': {'update': encoding}}


def objects():
    result = []
    for name, title in [('archives', 'wazuh-archives-*'), ('alerts', 'wazuh-alerts-*')]:
        result.append({'type': 'index-pattern', 'id': f'healthcare-{name}',
                       'attributes': {'title': title, 'timeFieldName': 'timestamp', 'fields': '[]'}})

    def search_source(pattern, query):
        return {'query': {'query': query, 'language': 'lucene'}, 'filter': [],
                'indexRefName': 'kibanaSavedObjectMeta.searchSourceJSON.index'}

    def panel(identity, title, pattern, query, fields=(), metric=None, search=False):
        references = [{'name': 'kibanaSavedObjectMeta.searchSourceJSON.index', 'type': 'index-pattern', 'id': f'healthcare-{pattern}'}]
        attrs = {'title': title, 'description': 'Candidate definition; validate mappings and import on the installed Wazuh version.',
                 'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps(search_source(pattern, query))}}
        if search:
            attrs.update(columns=list(fields), sort=[['timestamp', 'desc']], version=1)
            kind = 'search'
        else:
            kind = 'visualization'
            aggs = [{'id': '1', 'enabled': True, 'type': 'count', 'params': {}, 'schema': 'metric'}]
            if metric:
                aggs.append({'id': '2', 'enabled': True, 'type': metric[0], 'params': {'field': metric[1]}, 'schema': 'metric'})
            for index, field in enumerate(fields, 3):
                aggs.append({'id': str(index), 'enabled': True, 'type': 'terms', 'schema': 'bucket',
                             'params': {'field': field, 'orderBy': '1', 'order': 'desc', 'size': 20,
                                        'otherBucket': False, 'missingBucket': True, 'missingBucketLabel': 'Not applicable'}})
            attrs.update(uiStateJSON='{}', version=1,
                         visState=json.dumps({'title': title, 'type': 'table', 'aggs': aggs,
                                              'params': {'perPage': 10, 'showPartialRows': True, 'showTotal': False}}))
        result.append({'type': kind, 'id': f'healthcare-{identity}', 'attributes': attrs, 'references': references})

    hospital = 'data.service:"hospital-lab"'
    panel('activity', 'Hospital activity by action', 'archives', hospital, ['data.action'])
    panel('authentication', 'Failed authentication by actor', 'archives', hospital + ' AND data.action:"login_failure"', ['data.actor_id'])
    panel('records', 'Record reads and unique patients', 'archives', hospital + ' AND data.action:"record_read"',
          ['data.actor_id', 'data.care_scope'], ('cardinality', 'data.patient_id'))
    panel('documents', 'Document updates and native FIM by path', 'archives',
          'data.action:"document_update" OR rule.groups:"syscheck"', ['data.action', 'syscheck.path'])
    panel('exports', 'Export body bytes by destination approval', 'archives', hospital + ' AND data.action:"export_completed"',
          ['data.destination_id', 'data.destination_approved'], ('sum', 'data.bytes_sent'))
    alert_query = 'rule.id:(110101 OR 110102 OR 110103 OR 110201 OR 110301 OR 110302)'
    panel('alerts', 'Actionable alerts by rule and severity', 'alerts', alert_query, ['rule.id', 'rule.level'])
    panel('incidents', 'Latest actionable events raw counts are not incident counts', 'alerts', alert_query,
          ['timestamp', 'rule.id', 'rule.level', 'data.actor_id', 'data.action', 'data.run_id'], search=True)
    state = "length(data('latest')) == 0 || !isValid(data('latest')[0]._source.data.event_time) ? 'UNKNOWN' : (!isValid(toDate(data('latest')[0]._source.data.event_time)) || tick - toDate(data('latest')[0]._source.data.event_time) < -1000 ? 'UNKNOWN' : (tick - toDate(data('latest')[0]._source.data.event_time) > 90000 ? 'STALE' : 'FRESH'))"
    spec = {'$schema': 'https://vega.github.io/schema/vega/v5.json', 'width': 420, 'height': 110,
            'signals': [{'name': 'tick', 'init': 'now()', 'on': [{'events': {'type': 'timer', 'throttle': 1000}, 'update': 'now()'}]},
                        {'name': 'state', 'update': state}],
            'data': [{'name': 'latest', 'url': {'index': 'wazuh-archives-*', 'body': {
                'size': 1, '_source': ['data.event_time', 'timestamp'], 'sort': [{'timestamp': 'desc'}],
                'query': {'bool': {'filter': [{'term': {'data.service': 'hospital-lab'}},
                                             {'term': {'data.action': 'service_heartbeat'}}]}}}},
                      'format': {'property': 'hits.hits'}}],
            'marks': [text_mark({'signal': 'state'}, 45, 32,
                                {'signal': "state === 'FRESH' ? '#267344' : (state === 'STALE' ? '#a64621' : '#555555')"}),
                      text_mark({'value': 'Source heartbeat >90s stale; empty or bad clock unknown'}, 80, 12, {'value': '#555555'})]}
    result.append({'type': 'visualization', 'id': 'healthcare-health', 'references': [],
                   'attributes': {'title': 'Collection health 90 seconds stale empty unknown', 'description': 'Computed source-heartbeat status; refresh queries every 10 seconds. Check native agent connection state separately.',
                                  'visState': json.dumps({'title': 'Collection health', 'type': 'vega', 'params': {'spec': json.dumps(spec)}, 'aggs': []}),
                                  'uiStateJSON': '{}', 'version': 1,
                                  'kibanaSavedObjectMeta': {'searchSourceJSON': '{"query":{"query":"","language":"lucene"},"filter":[]}'}}})
    refs, panels = [], []
    for index, obj in enumerate(result[2:]):
        name = f'panel_{index}'
        refs.append({'name': name, 'type': obj['type'], 'id': obj['id']})
        panels.append({'panelIndex': str(index), 'panelRefName': name,
                       'gridData': {'x': (index % 2) * 24, 'y': (index // 2) * 15, 'w': 24, 'h': 15, 'i': str(index)},
                       'embeddableConfig': {}})
    result.append({'type': 'dashboard', 'id': 'healthcare-overview', 'references': refs,
                   'attributes': {'title': 'Healthcare SOC lab', 'description': 'Native import and field validation pending. Missing telemetry is unknown.',
                                  'panelsJSON': json.dumps(panels), 'optionsJSON': '{"useMargins":true,"hidePanelTitles":false}',
                                  'version': 1, 'timeRestore': False,
                                  'kibanaSavedObjectMeta': {'searchSourceJSON': '{"query":{"query":"","language":"lucene"},"filter":[]}'}}})
    return result


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[1] / 'siem/dashboard.ndjson'
    output.write_text(''.join(json.dumps(item) + '\n' for item in objects()), encoding='utf-8')
    print(f'Wrote {output}; fresh Wazuh import remains required.')
