import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from detector import normalize, detect


def fail(minute, ip='192.0.2.10', user='labuser'):
    return normalize({'source':'Security','event_id':4625,'timestamp':f'2026-10-14T12:{minute:02d}:00Z','host':'LAB-PC','ip_address':ip,'target_user_name':user})

def process(cmd):
    return normalize({'source':'Sysmon','event_id':1,'timestamp':'2026-10-14T12:00:00Z','host':'LAB-PC','image':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','command_line':cmd,'user':'LAB\\tester'})

class DetectorTests(unittest.TestCase):
    def test_failed_login_threshold(self):
        self.assertEqual(len(detect([fail(i) for i in range(5)])), 1)
    def test_below_threshold(self):
        self.assertEqual(len(detect([fail(i) for i in range(4)])), 0)
    def test_separate_ip_not_combined(self):
        self.assertEqual(len(detect([fail(i, '192.0.2.10') for i in range(3)]+[fail(i, '192.0.2.11') for i in range(3)])), 0)
    def test_outside_window(self):
        self.assertEqual(len(detect([fail(i) for i in [0, 5, 15, 25, 35]])), 0)
    def test_encoded_powershell(self):
        self.assertEqual(detect([process('powershell.exe -EncodedCommand AAA')])[0]['rule_id'], 'PS_SUSPICIOUS_ARGS')
    def test_normal_powershell(self):
        self.assertEqual(len(detect([process('powershell.exe -File approved.ps1')])), 0)
    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            normalize({'source':'Security','event_id':4625,'timestamp':'2026-10-14T12:00:00','host':'LAB-PC'})
    def test_invalid_event_pair_rejected(self):
        with self.assertRaises(ValueError):
            normalize({'source':'Sysmon','event_id':4625,'timestamp':'2026-10-14T12:00:00Z'})

if __name__ == '__main__':
    unittest.main()
