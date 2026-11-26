"""Classic Windows normalization and exact original evidence preservation."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'soc_agent'))
import parsers

class LegacyWindowsTests(unittest.TestCase):
    def event(self,eid,raw,source='windows.security'):
        return parsers.normalize_event({'source':source,'event_id':str(eid),'raw':raw,'message':raw,
                                        'host':'CORP','extra':{'record_number':123}})
    def test_failed_logon_keeps_original_evidence(self):
        raw='Logon Failure:\r\n User Name: SOC_ABSENT\r\n Domain: CORP\r\n Logon Type: 3\r\n Source Network Address: 127.0.0.1\r\n Source Port: 50123\r\n'
        ev=self.event(529,raw)
        self.assertEqual((ev['event_id'],ev['raw'],ev['message']),('529',raw,raw))
        self.assertEqual((ev['action'],ev['outcome'],ev['user'],ev['src_ip']),('logon_failed','failure','SOC_ABSENT','127.0.0.1'))
        self.assertEqual(ev['extra']['LogonType'],'3');self.assertEqual(ev['extra']['record_number'],123)
    def test_regular_group_not_misclassified_by_admin_actor(self):
        ev=self.event(636,'Member Added:\nMember Name: CORP\\SOC_LAB\nTarget Account Name: Users\nCaller User Name: Administrator\n')
        self.assertEqual(ev['action'],'member_added_to_group')
    def test_privileged_group_by_name(self):
        ev=self.event(636,'Member Added:\nMember Name: CORP\\SOC_LAB\nTarget Account Name: Administrators\n')
        self.assertEqual(ev['action'],'member_added_to_privileged_group');self.assertEqual(ev['extra']['group'],'Administrators')
    def test_real_crlf_group_member_id_fallback(self):
        ev=self.event(636,'Security Enabled Local Group Member Added:\r\n\tMember Name:\t-\r\n\tMember ID:\tCORP\\SOC_LAB261125\r\n\tTarget Account Name:\tAdministrators\r\n')
        self.assertEqual(ev['user'],'CORP\\SOC_LAB261125')
        self.assertNotIn('member name',ev['extra']['legacy_message_fields'])
    def test_602_is_not_always_created(self):
        self.assertEqual(self.event(602,'Scheduled task was deleted.\nTask Name: SOC_LAB')['action'],'scheduled_task_deleted')
        self.assertEqual(self.event(602,'Scheduled Task created:\nFile Name: SOC_LAB')['action'],'scheduled_task_created')
        self.assertEqual(self.event(602,'Task state changed.')['action'],'scheduled_task_changed')
    def test_application_529_not_security_authentication(self):
        self.assertNotEqual(self.event(529,'User Name: test',source='windows.application')['action'],'logon_failed')
    def test_original_audit_clear_id(self):
        ev=self.event(517,'The audit log was cleared.');self.assertEqual(ev['event_id'],'517');self.assertEqual(ev['action'],'audit_log_cleared')
    def test_modern_event_unchanged(self):
        ev=self.event(4625,'modern event');self.assertNotIn('legacy_normalizer',ev['extra'])
    def test_failure_type_is_preserved(self):
        ev=parsers.normalize_event({'source':'windows.security','event_id':'601','raw':'Service Name: SOC_LAB','extra':{'event_type':5}})
        self.assertEqual(ev['outcome'],'failure')
if __name__=='__main__':unittest.main(verbosity=2)
