# scanners/active_scan.py
import subprocess, time, shutil
import xml.etree.ElementTree as ET

def is_nmap_available():
    return shutil.which('nmap') is not None

def parse_nmap_xml(xml_text):
    ports = []
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                portid = port.get('portid')
                proto = port.get('protocol')
                state_node = port.find('state')
                state = state_node.get('state') if state_node is not None else ''
                service_node = port.find('service')
                service = service_node.get('name') if service_node is not None else ''
                raw = f"{portid}/{proto} {state} {service}"
                ports.append({'port': portid, 'protocol': proto, 'state': state, 'service': service, 'raw': raw})
    except Exception:
        # parsing failure -> return empty list but keep output available
        pass
    return ports

def run_nmap(target, ports=None, timeout=180):
    start = time.time()
    if not is_nmap_available():
        return {'error': 'nmap not installed on system', 'ports': [], 'duration': time.time() - start}
    args = ['nmap', '-sV', '--script', 'ssl-enum-ciphers', '-oX', '-', target]
    if ports:
        args = ['nmap', '-p', ports, '-sV', '--script', 'ssl-enum-ciphers', '-oX', '-', target]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout
        ports = parse_nmap_xml(out)
        return {'output': out, 'ports': ports, 'duration': time.time() - start}
    except subprocess.TimeoutExpired:
        return {'error': 'nmap timeout', 'ports': [], 'duration': time.time() - start}
    except Exception as e:
        return {'error': str(e), 'ports': [], 'duration': time.time() - start}
