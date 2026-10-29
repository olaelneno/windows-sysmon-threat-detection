"""Read exported Windows Event XML (single Event, Events root, or PowerShell XML fragments)."""
from pathlib import Path
import xml.etree.ElementTree as ET

MAX_FILE_BYTES = 25 * 1024 * 1024


def local_name(tag):
    return tag.rsplit('}', 1)[-1]


def child(parent, name):
    return next((x for x in parent if local_name(x.tag) == name), None) if parent is not None else None


def text_at(parent, name):
    node = child(parent, name)
    return (node.text or '').strip() if node is not None else ''


def parse_xml_events(path):
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('XML export exceeds 25 MB; split into smaller exports')
    content = path.read_text(encoding='utf-8-sig').strip()
    # Supports one Event, an Events container, or adjacent Event fragments from ToXml().
    if content.startswith('<?xml'):
        content = content.split('?>', 1)[1].strip()
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Only wrap repeated event fragments, not arbitrary malformed XML.
        try:
            root = ET.fromstring('<Events>' + content + '</Events>')
        except ET.ParseError as exc:
            raise ValueError(f'invalid event XML: {exc}') from exc
    nodes = [root] if local_name(root.tag) == 'Event' else [x for x in root if local_name(x.tag) == 'Event']
    if not nodes:
        raise ValueError('no Event elements found')
    events = []
    skipped = 0
    for event in nodes:
        system = child(event, 'System')
        event_id_text = text_at(system, 'EventID')
        channel = text_at(system, 'Channel')
        provider = child(system, 'Provider')
        provider_name = provider.attrib.get('Name', '') if provider is not None else ''
        source = ('Sysmon' if ('sysmon' in provider_name.lower() or 'sysmon' in channel.lower())
                  else 'Security' if channel.lower() == 'security' else None)
        try:
            event_id = int(event_id_text)
        except ValueError:
            skipped += 1
            continue
        if (source, event_id) not in (('Security', 4625), ('Sysmon', 1)):
            skipped += 1
            continue
        time_node = child(system, 'TimeCreated')
        timestamp = time_node.attrib.get('SystemTime', '') if time_node is not None else ''
        host = text_at(system, 'Computer')
        data = child(event, 'EventData')
        fields = {}
        if data is not None:
            for field in data:
                if local_name(field.tag) == 'Data' and field.attrib.get('Name'):
                    fields[field.attrib['Name']] = field.text or ''
        common = {'source': source, 'event_id': event_id, 'timestamp': timestamp, 'host': host}
        if source == 'Security':
            common.update(ip_address=fields.get('IpAddress', ''), target_user_name=fields.get('TargetUserName', ''))
        else:
            common.update(image=fields.get('Image', ''), command_line=fields.get('CommandLine', ''), user=fields.get('User', ''))
        events.append(common)
    return events, skipped
