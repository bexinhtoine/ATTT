"""Check that comparison UI preserves unknowns and the meaning of evidence IDs."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'soc_server'))
from app.comparison_results import comparison_rows, comparison_summary
from app.comparison_explanations import rule_definitions, feature_guide
from app import create_app
from app.extensions import db
from app.models import User, DetectionRule
from config import Config


class ComparisonTests(unittest.TestCase):
    def test_reference_is_not_a_count_and_host_is_not_all_run_hosts(self):
        rows = comparison_rows({'rules': [dict(code='R01', name='clear', hosts=['WRONG', 'ALL'],
                soc='Có cảnh báo #89 · event #29152', elastic='2 cảnh báo native', wazuh='2 cảnh báo native')]},
                {29152: SimpleNamespace(host='CORP')})
        self.assertEqual(rows[0]['cells']['soc']['alert_id'], 89)
        self.assertIsNone(rows[0]['cells']['soc']['count'])
        self.assertEqual(rows[0]['evidence_host'], 'CORP')
        self.assertFalse(rows[0]['differs'])

    def test_zero_is_not_missing_and_builtin_rule_is_retained(self):
        report = {'rules': [dict(code='R17', name='spray', soc='Có cảnh báo #85 · event #30655',
                                elastic='1 cảnh báo native', wazuh='0 cảnh báo native'),
                            dict(code='R09', name='sudo', soc='', elastic='Chưa đo',
                                 wazuh='2 cảnh báo native qua luật có sẵn2501')]}
        rows = comparison_rows(report)
        self.assertIs(rows[0]['cells']['wazuh']['present'], False)
        self.assertIsNone(rows[1]['cells']['elastic']['present'])
        self.assertEqual(rows[1]['cells']['wazuh']['builtin'], '2501')
        self.assertTrue(rows[0]['differs'])
        self.assertEqual(comparison_summary(rows)['wazuh'], dict(detected=1, not_seen=1, unknown=0))

    def test_different_counts_are_not_a_winner(self):
        row = comparison_rows({'rules':[dict(code='R15', soc='Có cảnh báo #1 · event #2',
                              elastic='1 cảnh báo native', wazuh='9 cảnh báo native')]})[0]
        self.assertTrue(row['differs'])
        self.assertIn('cách đếm và gộp', row['difference'])

    def test_no_vendor_config_from_a_different_run(self):
        rule = SimpleNamespace(code='R17', rule_type='threshold', conditions_dict={'action':['logon_failed','invalid_user']},
                               threshold_count=5, window_seconds=300, group_by='src_ip', distinct_field='user_name')
        defs = rule_definitions([rule], run_id='UNRELATED_RUN')['R17']
        self.assertIsNone(defs['elastic']['config'])
        self.assertIsNone(defs['wazuh']['config'])
        self.assertIn('tên tài khoản khác nhau', defs['soc']['explanation'])


class ComparisonRenderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='soc_comparison_ui_')
        class C(Config):
            TESTING = True
            SECRET_KEY = 'comparison-test-only'
            ENROLLMENT_TOKEN = 'comparison-test-only'
            SQLALCHEMY_DATABASE_URI = 'sqlite:///' + (Path(cls.tmp.name)/'test.db').as_posix()
            PLATFORM_RESULTS_DIR = str(Path(cls.tmp.name)/'platforms')
            ANTHROPIC_API_KEY = None
            OPENAI_API_KEY = None
        cls.app = create_app(C, start_background=False)

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.session.remove()
            db.engine.dispose()
        cls.tmp.cleanup()

    def test_current_report_and_all_feature_comparisons_render(self):
        from app.platforms import FEATURES
        from flask import url_for
        with self.app.app_context():
            client = self.app.test_client()
            with client.session_transaction() as session:
                session['user_id'] = User.query.filter_by(role='admin').first().id
            page = client.get('/comparison?platform=all')
            self.assertEqual(page.status_code, 200)
            html = page.get_data(as_text=True)
            self.assertIn('Khác nhau ở đâu?', html)
            self.assertIn('chưa có tổng số theo từng luật', html)
            self.assertNotIn('2 cảnh báo native', html)
            self.assertEqual(html.count('data-comparison-row '), 21)
            for feature, (_, endpoint, _) in FEATURES.items():
                with self.subTest(feature=feature):
                    with self.app.test_request_context():
                        path = url_for(endpoint, platform='all')
                    page = client.get(path)
                    self.assertEqual(page.status_code, 200)
                    text = page.get_data(as_text=True)
                    self.assertIn('Cách so sánh chức năng', text)
                    self.assertIn('Điều có thể kết luận:', text)
                    self.assertIn('chưa được nối hoặc chưa thử', text)
                    if feature == 'rules':
                        self.assertIn('Đối chiếu điều kiện của 21 luật', text)
                        self.assertIn('different_field', text)

    def test_exported_rules_are_shown_as_lab_configuration(self):
        with self.app.app_context():
            rules = DetectionRule.query.filter(DetectionRule.code.in_(['R01','R17','R19'])).all()
            defs = rule_definitions(rules, 'SOC_NATIVE_COMMANDS_20261125')
            self.assertEqual(defs['R17']['elastic']['config']['threshold']['cardinality'][0]['value'], 5)
            self.assertEqual(defs['R17']['wazuh']['config']['timeframe'], '300')
            self.assertIn('100740', defs['R17']['wazuh']['explanation'])
            self.assertIn('web_not_found', defs['R19']['elastic']['explanation'])
            self.assertIn('không phải luật mặc định', defs['R01']['elastic']['origin'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
