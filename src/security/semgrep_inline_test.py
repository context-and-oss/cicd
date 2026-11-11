"""Adapter mechanics; the pinned-engine smoke proves actual detection."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import semgrep_inline as adapter
from semgrep_inline import DOM_ID, InlineError, Scripts, SourceMap, analyse, extract, remap_sarif


class InlineTests(unittest.TestCase):
    def test_script_types_and_inert_contexts(self):
        script = "const value = 1;"
        cases = {
            "<ScRiPt>" + script + "</sCrIpT>": 1,
            '<script type="module">' + script + '</script>': 1,
            '<script type="text/javascript">' + script + '</script>': 1,
            '<script language="JavaScript1.2">' + script + '</script>': 1,
            '<script type="" language="unknown">' + script + '</script>': 1,
            '<script type="application/json" type="module">{}</script>': 0,
            '<script type="module" type="application/json">' + script + '</script>': 1,
            '<script type="application/json">{}</script>': 0,
            '<script type="importmap">{}</script>': 0,
            '<script type="text/x-template">' + script + '</script>': 0,
            '<script src="local.js">' + script + '</script>': 0,
            '<script src="">' + script + '</script>': 0,
            '<template><script>' + script + '</script></template>': 1,
            '<textarea><script>' + script + '</script></textarea>': 0,
            '<textarea/><script>' + script + '</script></textarea>': 0,
            '<title><script>' + script + '</script></title>': 0,
            '<noscript><script>' + script + '</script></noscript>': 0,
            '<plaintext><script>' + script + '</script>': 0,
            '<script>const value="&lt;";</script>': 1,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                parser = Scripts(text)
                self.assertEqual(len(parser.extract()), expected)
                self.assertFalse(parser.issues)
        self.assertIn(b'"&lt;"', Scripts('<script>const value="&lt;";</script>').extract()[0][1])

    def test_template_scripts_are_not_joined_to_the_active_document(self):
        text = '<script>const source=read();</script><template><script>use(source);</script></template>'
        blocks = Scripts(text).extract()
        self.assertEqual([block[2] for block in blocks], [False, True])

    def test_raw_text_does_not_hide_a_following_real_script(self):
        text = '<textarea><script>not code</textarea><script>run();</script>'
        self.assertEqual([b[1] for b in Scripts(text).extract()], [b'run();'])

    def test_unsupported_markup_is_disclosed(self):
        for text in ['<script>unfinished', '<script/>run();</script>',
                     '<script><!--<script>nested</script>--></script>',
                     '<svg><script>run();</script></svg>']:
            parser = Scripts(text)
            parser.extract()
            self.assertTrue(parser.issues, text)

    def test_selection_and_script_scopes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'output'
            output.mkdir()
            (root / 'page.htm').write_text('<script>first();//comment</script><script>second();</script><script type="module">third();</script>')
            (root / 'excluded.html').write_text('<script>excluded();</script>')
            maps, warnings = extract(['page.htm'], root, output)
            self.assertEqual(len(maps), 2)
            self.assertFalse(warnings)
            classic, module = maps.values()
            self.assertEqual(classic.generated, b'first();//comment\n;\nsecond();\n;\n')
            self.assertEqual(module.generated, b'third();\n;\n')
            self.assertNotIn(b'excluded', classic.generated)
            with self.assertRaises(InlineError):
                extract(['../outside.html'], root, output)

    def test_non_utf8_input_is_partial_not_an_empty_clean_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'page.html').write_bytes(b'<script>\xff</script>')
            maps, warnings = extract(['page.html'], root, root)
            self.assertFalse(maps)
            self.assertIn('non-UTF-8', warnings[0])

    def test_locations_include_unicode_classic_boundaries_and_codeflows(self):
        source = 'é😀<script>first();</script>\n<script>second();</script>'.encode()
        blocks = Scripts(source.decode()).extract()
        mapping = SourceMap('page.html', source, blocks)
        region = {'startLine': 1, 'startColumn': 1, 'endLine': 1, 'endColumn': 9}
        document = {'runs': [{'artifacts': [], 'tool': {'driver': {}},
            'results': [{'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': 'scripts/inline-0000.js'},
                'region': copy.deepcopy(region),
                'contextRegion': {'startLine': 9999}}}],
                'codeFlows': [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {
                    'artifactLocation': {'uri': 'scripts/inline-0000.js'},
                    'region': {'startLine': 3, 'startColumn': 1}}}}]}]}]}],
            'invocations': [{'toolExecutionNotifications': [{'message': {
                'text': 'Syntax error at line scripts/inline-0000.js:3: `source`'}}]}]}]}
        remap_sarif(document, {'inline-0000.js': mapping}, {})
        result = document['runs'][0]['results'][0]
        physical = result['locations'][0]['physicalLocation']
        self.assertEqual(physical['artifactLocation']['uri'], 'page.html')
        self.assertNotIn('contextRegion', physical)
        self.assertEqual(physical['region']['startColumn'], 12)  # é=1, emoji=2, tag=8.
        flow = result['codeFlows'][0]['threadFlows'][0]['locations'][0]['location']['physicalLocation']
        self.assertEqual(flow['region'], {'startLine': 2, 'startColumn': 9})
        self.assertNotIn('inline-0000', json.dumps(document))
        self.assertEqual(document['runs'][0]['columnKind'], 'utf16CodeUnits')
        with self.assertRaises(InlineError):
            mapping.position(9999)

    def test_internal_failures_do_not_publish_a_clean_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{"files":[],"floor":[]}')
            (root / 'page.html').write_text('<script>run();</script>')
            (root / 'report').write_text('{"paths":{"scanned":["page.html"]}}')
            baseline = '{"runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[]}]}'
            (root / 'sarif').write_text(baseline)
            args = (root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
            with patch('semgrep_inline.rules_for_inline', return_value=[{'id': DOM_ID}]), \
                 patch('semgrep_inline.subprocess.run', side_effect=OSError('source must not escape')):
                with self.assertRaises(OSError):
                    analyse(*args)
            self.assertEqual((root / 'sarif').read_text(), baseline)
            self.assertFalse((root / 'warnings').exists())

    def test_cancellation_does_not_publish_partial_inline_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{}')
            (root / 'page.html').write_text('<script>run();</script>')
            (root / 'report').write_text('{"paths":{"scanned":["page.html"]}}')
            baseline = '{"runs":[{}]}'
            (root / 'sarif').write_text(baseline)
            with patch('semgrep_inline.rules_for_inline', return_value=[{'id': DOM_ID}]), \
                 patch('semgrep_inline.subprocess.run', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
            self.assertEqual((root / 'sarif').read_text(), baseline)
            self.assertFalse((root / 'warnings').exists())

    def test_indexed_artifacts_and_unicode_inside_javascript(self):
        source = '<script>const text="é😀"; run();</script>'.encode()
        mapping = SourceMap('original.html', source, Scripts(source.decode()).extract())
        column = mapping.generated.index(b'run()') + 1
        document = {'runs': [{'artifacts': [{'location': {'uri': 'scripts/inline-0000.js'},
                                            'contents': {'text': 'must be withheld'}}],
            'results': [{'locations': [{'physicalLocation': {'artifactLocation': {'index': 0},
                'region': {'startLine': 1, 'startColumn': column}}}]}]}]}
        remap_sarif(document, {'inline-0000.js': mapping}, {})
        run = document['runs'][0]
        self.assertEqual(run['artifacts'][0]['location']['uri'], 'original.html')
        self.assertNotIn('contents', run['artifacts'][0])
        physical = run['results'][0]['locations'][0]['physicalLocation']
        expected = len(source[:source.index(b'run()')].decode().encode('utf-16-le')) // 2 + 1
        self.assertEqual(physical['region']['startColumn'], expected)
        self.assertEqual(physical['artifactLocation']['uri'], 'original.html')

    def test_original_uri_is_encoded_not_treated_as_a_fragment(self):
        source = b'<script>run();</script>'
        mapping = SourceMap('sp ace/#page.html', source, Scripts(source.decode()).extract())
        document = {'runs': [{'results': [{'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': 'scripts/inline-0000.js'},
            'region': {'startLine': 1, 'startColumn': 1}}}]}]}]}
        remap_sarif(document, {'inline-0000.js': mapping}, {})
        uri = document['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
        self.assertEqual(uri, 'sp%20ace/%23page.html')

    def test_atomic_publication_keeps_baseline_on_io_failure(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{}')
            (root / 'page.html').write_text('<script>run();</script>')
            (root / 'report').write_text('{"paths":{"scanned":["page.html"]}}')
            baseline = '{"runs":[{}]}'
            (root / 'sarif').write_text(baseline)
            def fake_scan(command, cwd, **kwargs):
                work = Path(cwd)
                (work / 'report.json').write_text('{"paths":{"scanned":["scripts/inline-0000.js"]},"time":{"fixpoint_timeouts":[]}}')
                (work / 'report.sarif').write_text(json.dumps({'runs': [{
                    'tool': {'driver': {'rules': [{'id': DOM_ID}]}}, 'results': []}]}))
                return SimpleNamespace(returncode=0)
            with patch('semgrep_inline.rules_for_inline', return_value=[{'id': DOM_ID}]), \
                 patch('semgrep_inline.subprocess.run', side_effect=fake_scan), \
                 patch.object(Path, 'replace', side_effect=OSError('publication failed')):
                with self.assertRaises(OSError):
                    analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
            self.assertEqual((root / 'sarif').read_text(), baseline)

    def test_inline_scan_waits_for_completion_and_disables_optional_probe(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{}')
            (root / 'page.html').write_text('<script>first();</script><script>second();</script>')
            (root / 'report').write_text('{"paths":{"scanned":["page.html"]}}')
            (root / 'sarif').write_text('{"runs":[{}]}')
            def fake_scan(command, cwd, **kwargs):
                self.assertEqual(command[:2], ['semgrep', 'scan'])
                self.assertIn('--disable-version-check', command)
                self.assertIn('--metrics=off', command)
                self.assertIn('--no-rewrite-rule-ids', command)
                self.assertIn('--time', command)
                self.assertNotIn('timeout', kwargs)  # The caller owns execution lifetime.
                self.assertEqual(command[-1], 'scripts')
                work = Path(cwd)
                self.assertEqual((work / 'scripts/inline-0000.js').read_text(), 'first();\n;\nsecond();\n;\n')
                (work / 'report.json').write_text('{"paths":{"scanned":["scripts/inline-0000.js"]},"time":{"fixpoint_timeouts":[]}}')
                (work / 'report.sarif').write_text(json.dumps({'runs': [{
                    'tool': {'driver': {'rules': [{'id': DOM_ID}]}}, 'results': []}]}))
                return SimpleNamespace(returncode=0)
            with patch('semgrep_inline.rules_for_inline', return_value=[{'id': DOM_ID}]), \
                 patch('semgrep_inline.subprocess.run', side_effect=fake_scan) as runner:
                analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
            runner.assert_called_once()  # No batching, scope splitting or retry.

    def test_inline_metadata_comes_from_its_own_scan_before_remapping(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{}')
            (root / 'page.html').write_text('<script>run();</script>')
            (root / 'report').write_text(json.dumps({
                'paths': {'scanned': ['page.html']},
                'results': [{'check_id': DOM_ID, 'extra': {'metadata': {'category': 'style'}}}],
            }))
            (root / 'sarif').write_text('{"runs":[{}]}')
            def fake_scan(command, cwd, **kwargs):
                work = Path(cwd)
                (work / 'report.json').write_text(json.dumps({
                    'paths': {'scanned': ['scripts/inline-0000.js']},
                    'time': {'fixpoint_timeouts': []},
                    'results': [{'check_id': DOM_ID, 'extra': {'metadata': {
                        'category': 'security', 'confidence': 'LOW', 'subcategory': ['audit'],
                    }}}],
                }))
                (work / 'report.sarif').write_text(json.dumps({'runs': [{
                    'tool': {'driver': {'rules': [{'id': DOM_ID}]}},
                    'results': [{'ruleId': DOM_ID, 'message': {'text': 'synthetic'},
                        'locations': [{'physicalLocation': {
                            'artifactLocation': {'uri': 'scripts/inline-0000.js'},
                            'region': {'startLine': 1, 'startColumn': 1},
                        }}]}],
                }]}))
                return SimpleNamespace(returncode=0)
            with patch('semgrep_inline.rules_for_inline', return_value=[{'id': DOM_ID}]), \
                 patch('semgrep_inline.subprocess.run', side_effect=fake_scan):
                analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
            document = json.loads((root / 'sarif').read_text())
            row = document['runs'][1]['results'][0]
            self.assertEqual(row['properties']['cicdFindingMetadata']['category'], 'security')
            self.assertEqual(row['properties']['cicdFindingMetadata']['confidence'], 'LOW')
            self.assertEqual(row['properties']['cicdFindingMetadata']['subcategories'], ['audit'])
            self.assertEqual(row['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'page.html')

    def test_empty_static_html_needs_no_second_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{}')
            (root / 'page.html').write_text('<p>Static</p>')
            (root / 'report').write_text('{"paths":{"scanned":["page.html"]}}')
            (root / 'sarif').write_text('{"runs":[{}]}')
            with patch('semgrep_inline.subprocess.run') as runner:
                analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
            runner.assert_not_called()
            self.assertEqual(json.loads((root / 'warnings').read_text()), [])

    def test_secondary_scan_must_cover_inputs_and_rules(self):
        from types import SimpleNamespace
        for omitted in ['input', 'rule', 'run', 'exit']:
            with self.subTest(omitted=omitted), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'plan').write_text('{}')
                (root / 'page.html').write_text('<script>run();</script>')
                (root / 'report').write_text('{"paths":{"scanned":["page.html"]}}')
                baseline = '{"runs":[{}]}'
                (root / 'sarif').write_text(baseline)
                def fake_scan(command, cwd, **kwargs):
                    work = Path(cwd)
                    scanned = [] if omitted == 'input' else ['scripts/inline-0000.js']
                    (work / 'report.json').write_text(json.dumps({'paths': {'scanned': scanned}, 'time': {'fixpoint_timeouts': []}}))
                    rules = [] if omitted == 'rule' else [{'id': DOM_ID}]
                    runs = [] if omitted == 'run' else [{'tool': {'driver': {'rules': rules}}, 'results': []}]
                    (work / 'report.sarif').write_text(json.dumps({'runs': runs}))
                    return SimpleNamespace(returncode=2 if omitted == 'exit' else 0)
                with patch('semgrep_inline.rules_for_inline', return_value=[{'id': DOM_ID}]), \
                     patch('semgrep_inline.subprocess.run', side_effect=fake_scan):
                    with self.assertRaises(InlineError):
                        analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
                self.assertEqual((root / 'sarif').read_text(), baseline)

    def test_fixpoint_notices_are_authored_mapped_and_do_not_copy_source(self):
        source = 'é😀<script>run();</script>'.encode()
        maps = {'inline-0000.js': SourceMap('sp ace/#panel.html', source, Scripts(source.decode()).extract())}
        report = {'time': {'fixpoint_timeouts': [{'error_type': 'Fixpoint timeout', 'severity': 'warn',
            'message': 'RAW SOURCE must not escape, including unquoted values',
            'location': {'path': 'scripts/inline-0000.js',
                         'start': {'line': 1, 'col': 1, 'offset': 0},
                         'end': {'line': 1, 'col': 2, 'offset': 1}}}]}}
        sarif = {'runs': [{'invocations': [{'executionSuccessful': True, 'toolExecutionNotifications': []}]}]}
        adapter.add_fixpoint_notifications(report, sarif, maps)
        remap_sarif(sarif, maps, {})
        note = sarif['runs'][0]['invocations'][0]['toolExecutionNotifications'][0]
        self.assertEqual(note['descriptor']['id'], 'Fixpoint timeout')
        self.assertEqual(note['level'], 'warning')
        physical = note['locations'][0]['physicalLocation']
        self.assertEqual(physical['artifactLocation']['uri'], 'sp%20ace/%23panel.html')
        self.assertEqual(physical['region']['startColumn'], 12)
        self.assertNotIn('RAW SOURCE', json.dumps(sarif))
        self.assertNotIn('inline-0000', json.dumps(sarif))

    def test_unattributed_fixpoint_notice_is_still_counted(self):
        report = {'time': {'fixpoint_timeouts': [{'error_type': 'Fixpoint timeout', 'severity': 'warn'}]}}
        sarif = {'runs': [{}]}
        adapter.add_fixpoint_notifications(report, sarif, {})
        notices = sarif['runs'][0]['invocations'][0]['toolExecutionNotifications']
        self.assertEqual(len(notices), 1)
        self.assertNotIn('locations', notices[0])

    def test_malformed_or_unknown_diagnostics_are_not_zero_warnings(self):
        warning = {'error_type': 'Fixpoint timeout', 'severity': 'warn'}
        for report in [{}, {'time': None}, {'time': {}}, {'time': {'fixpoint_timeouts': None}},
                       {'time': {'fixpoint_timeouts': [None]}},
                       {'time': {'fixpoint_timeouts': [dict(warning, severity='error')]}},
                       {'time': {'fixpoint_timeouts': [dict(warning, error_type='unknown')]}}]:
            with self.subTest(report=report), self.assertRaises(InlineError):
                adapter.add_fixpoint_notifications(report, {'runs': [{}]}, {})
        for path in ['scripts/unknown.js', '../scripts/inline-0000.js', '/outside/inline-0000.js']:
            report = {'time': {'fixpoint_timeouts': [dict(warning, location={
                'path': path, 'start': {'line': 1, 'col': 1}})]}}
            with self.subTest(path=path), self.assertRaises(InlineError):
                adapter.add_fixpoint_notifications(report, {'runs': [{}]}, {'inline-0000.js': None})
        with self.assertRaises(InlineError):
            adapter.add_fixpoint_notifications({'time': {'fixpoint_timeouts': [warning]}}, {'runs': [{}, {}]}, {})

    def test_bad_profile_never_publishes_inline_success(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{}')
            (root / 'page.html').write_text('<script>run();</script>')
            (root / 'report').write_text('{"paths":{"scanned":["page.html"]}}')
            baseline = '{"runs":[{}]}'
            (root / 'sarif').write_text(baseline)
            def fake_scan(command, cwd, **kwargs):
                work = Path(cwd)
                (work / 'report.json').write_text('{"paths":{"scanned":["scripts/inline-0000.js"]},"time":{}}')
                (work / 'report.sarif').write_text(json.dumps({'runs': [{
                    'tool': {'driver': {'rules': [{'id': DOM_ID}]}}, 'results': []}]}))
                return SimpleNamespace(returncode=0)
            with patch('semgrep_inline.rules_for_inline', return_value=[{'id': DOM_ID}]), \
                 patch('semgrep_inline.subprocess.run', side_effect=fake_scan):
                with self.assertRaises(InlineError):
                    analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')
            self.assertEqual((root / 'sarif').read_text(), baseline)
            self.assertFalse((root / 'warnings').exists())

    def test_missing_inventory_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan').write_text('{}')
            (root / 'report').write_text('{"paths":{"scanned":null}}')
            with self.assertRaises(InlineError):
                analyse(root / 'plan', root, root / 'report', root / 'sarif', root / 'warnings')


if __name__ == '__main__':
    unittest.main()
