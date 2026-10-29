import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from detector import load_events, detect
from xml_parser import parse_xml_events

SAMPLE = Path(__file__).resolve().parents[1] / 'data' / 'sample_events.xml'

class XmlParserTests(unittest.TestCase):
    def test_namespaced_export_and_unsupported_skipped(self):
        raw, skipped = parse_xml_events(SAMPLE)
        self.assertEqual((len(raw), skipped), (6, 1))
    def test_detection_on_xml(self):
        alerts = detect(load_events(SAMPLE))
        self.assertEqual({x['rule_id'] for x in alerts}, {'REPEATED_FAILED_LOGINS', 'PS_SUSPICIOUS_ARGS'})
    def test_adjacent_fragments(self):
        text = SAMPLE.read_text()
        text = text.replace('<Events>','').replace('</Events>','')
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'events.xml'; p.write_text(text)
            self.assertEqual(len(parse_xml_events(p)[0]), 6)
    def test_single_event(self):
        from xml.etree import ElementTree as ET
        root = ET.parse(SAMPLE).getroot()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'one.xml'; p.write_bytes(ET.tostring(root[0],encoding='utf-8'))
            self.assertEqual(len(parse_xml_events(p)[0]), 1)
    def test_malformed_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'bad.xml'; p.write_text('<Event><System>')
            with self.assertRaises(ValueError): parse_xml_events(p)

if __name__ == '__main__': unittest.main()
