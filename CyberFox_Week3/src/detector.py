"""Offline Windows/Sysmon JSON event detection MVP (standard library only)."""
import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml_parser import parse_xml_events


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be a string')
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp must include timezone')
    return dt.astimezone(timezone.utc)


def normalize(raw):
    if not isinstance(raw, dict):
        raise ValueError('event must be a JSON object')
    event_id = int(raw['event_id'])
    source = raw['source']
    if source not in ('Security', 'Sysmon'):
        raise ValueError('unsupported source')
    if (source, event_id) not in (('Security', 4625), ('Sysmon', 1)):
        raise ValueError('unsupported source/event_id combination')
    timestamp = parse_time(raw['timestamp'])
    return {**raw, 'event_id': event_id, 'timestamp': timestamp.isoformat(), '_dt': timestamp}


def detect(events, threshold=5, window_minutes=10):
    """Detect repeated 4625 failures by host, source IP and target username, plus flagged process arguments."""
    if threshold < 2 or window_minutes < 1:
        raise ValueError('threshold >=2 and window_minutes >=1 required')
    alerts = []
    groups = defaultdict(list)
    for event in events:
        if event['source'] == 'Security' and event['event_id'] == 4625:
            ip = str(event.get('ip_address', '')).strip()
            user = str(event.get('target_user_name', '')).strip()
            host = str(event.get('host', '')).strip()
            if ip and ip not in ('-', '127.0.0.1', '::1') and user and host:
                groups[(host, ip, user)].append(event)
        elif event['source'] == 'Sysmon' and event['event_id'] == 1:
            image = str(event.get('image', '')).replace('/', '\\').lower().rsplit('\\', 1)[-1]
            cmd = str(event.get('command_line', '')).lower()
            indicators = []
            if image in ('powershell.exe', 'pwsh.exe'):
                if '-encodedcommand' in cmd or ' -enc ' in f' {cmd} ':
                    indicators.append('encoded PowerShell command argument')
                if '-noprofile' in cmd and '-windowstyle hidden' in cmd:
                    indicators.append('hidden PowerShell with no profile')
            if indicators:
                alerts.append({'rule_id': 'PS_SUSPICIOUS_ARGS', 'severity': 'medium',
                    'timestamp': event['timestamp'], 'host': event.get('host', 'unknown'),
                    'user': event.get('user', 'unknown'), 'source': 'Sysmon', 'event_id': 1,
                    'reason': '; '.join(indicators), 'evidence': {'image': event.get('image'), 'command_line': event.get('command_line')}})
    window = timedelta(minutes=window_minutes)
    for (host, ip, user), group in groups.items():
        group.sort(key=lambda e: e['_dt'])
        left = 0
        # Emit at most one alert per contiguous burst; re-arm when window expires.
        last_alert_time = None
        for right, event in enumerate(group):
            while event['_dt'] - group[left]['_dt'] > window:
                left += 1
            if right - left + 1 >= threshold and (last_alert_time is None or event['_dt'] - last_alert_time > window):
                alerts.append({'rule_id': 'REPEATED_FAILED_LOGINS', 'severity': 'high',
                    'timestamp': event['timestamp'], 'host': host, 'user': user, 'source': 'Security', 'event_id': 4625,
                    'reason': f'{right-left+1} failed logons from {ip} targeting {user} within {window_minutes} minutes',
                    'evidence': {'ip_address': ip, 'target_user_name': user, 'count': right-left+1}})
                last_alert_time = event['_dt']
    return sorted(alerts, key=lambda a: (a['timestamp'], a['rule_id']))


def load_events(path):
    if Path(path).suffix.lower() == '.xml':
        raw, skipped = parse_xml_events(path)
        print(f'XML parser: {len(raw)} supported events, {skipped} unsupported events skipped')
        return [normalize(x) for x in raw]
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError('input must be a JSON array')
    return [normalize(x) for x in data]


def main():
    parser = argparse.ArgumentParser(description='Analyze normalized JSON or exported Windows/Sysmon XML events')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', default='output/alerts.json')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window-minutes', type=int, default=10)
    args = parser.parse_args()
    events = load_events(args.input)
    alerts = detect(events, args.threshold, args.window_minutes)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(alerts, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'Processed {len(events)} events; generated {len(alerts)} alerts -> {output}')
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['rule_id']} | {alert['timestamp']} | {alert['reason']}")

if __name__ == '__main__':
    main()
