import sys,unittest
from pathlib import Path
from datetime import datetime,timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'soc_server'))
from app.time_inputs import parse_form_datetime

class LocalFormTimeTests(unittest.TestCase):
    def test_vietnam_form_time_matches_stored_utc(self):
        self.assertEqual(parse_form_datetime('2026-11-25T18:30','Asia/Ho_Chi_Minh'),datetime(2026,11,25,11,30,tzinfo=timezone.utc))
    def test_explicit_utc_and_offsets_are_preserved(self):
        for value in ('2026-11-25T11:30Z','2026-11-25T18:30+07:00'):
            self.assertEqual(parse_form_datetime(value,'Asia/Ho_Chi_Minh'),datetime(2026,11,25,11,30,tzinfo=timezone.utc))
    def test_invalid_or_empty_is_absent(self):
        for value in ('',None,'not a date'):
            self.assertIsNone(parse_form_datetime(value,'Asia/Ho_Chi_Minh'))
if __name__=='__main__':unittest.main(verbosity=2)
