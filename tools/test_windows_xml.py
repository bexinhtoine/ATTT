"""Exercise the actual wevtutil document shape through the Windows collector."""
import sys,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'soc_agent'))
import parsers,collectors

def event(record=101):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID><Level>3</Level><TimeCreated SystemTime="2026-11-25T09:43:41Z"/><EventRecordID>{record}</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>real-host</Computer></System><EventData><Data Name="ScriptBlockText">[Convert]::FromBase64String('U09DX0xBQg==')</Data></EventData></Event>'''

class WindowsXmlTests(unittest.TestCase):
    def test_real_document_formats(self):
        for xml in (event(),'<Events>'+event()+'</Events>', '<?xml version="1.0"?><Events>'+event()+'</Events>', '<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'+event()+'</Events>'):
            with self.subTest(xml=xml[:45]):
                e=parsers.parse_windows_event_xml(xml)
                self.assertEqual(len(e),1)
                self.assertEqual((e[0]['event_id'],e[0]['action'],e[0]['extra']['record_id']),('4104','powershell_suspicious_script','101'))
    def test_multiple_bare_events_and_empty_document(self):
        self.assertEqual(len(parsers.parse_windows_event_xml(event()+event(102))),2)
        self.assertEqual(parsers.parse_windows_event_xml('<Events/>'),[])
    def test_collector_baseline_then_next_record_with_wevtutil_wrapper(self):
        c=collectors.WindowsEventLogCollector('ps','Microsoft-Windows-PowerShell/Operational',state={})
        responses=[SimpleNamespace(returncode=0,stdout=('<Events>'+event()+'</Events>').encode(),stderr=b''),SimpleNamespace(returncode=0,stdout=('<Events>'+event(102)+'</Events>').encode(),stderr=b'')]
        with patch.object(collectors,'IS_WINDOWS',True),patch.object(collectors.subprocess,'run',side_effect=responses):
            self.assertEqual(c.collect(),[])
            self.assertEqual(c.state['last_record'],101)
            fresh=c.collect()
            self.assertEqual(len(fresh),1)
            self.assertEqual(c.state['last_record'],102)
    def test_unrelated_container_not_recursively_ingested(self):
        self.assertEqual(parsers.parse_windows_event_xml('<Other>'+event()+'</Other>'),[])

if __name__=='__main__':unittest.main(verbosity=2)
