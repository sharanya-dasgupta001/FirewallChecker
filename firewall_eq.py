from z3 import *

# Declare symbolic variables
src = Int('src')
dst = Int('dst')

# Define the matches function
def matches(srcLower, srcUpper, dstLower, dstUpper):
    return And(
        srcLower <= src, src <= srcUpper,
        dstLower <= dst, dst <= dstUpper
    )

# Define firewall1 and firewall2 as Boolean expressions
firewall1 = And(
    matches(0, 10, 20, 30),
    Not(matches(5, 10, 25, 30))
)

firewall2 = And(
    matches(1, 10, 20, 30),
    Not(matches(5, 10, 25, 30))
)

# Create the solver
s = Solver()

# Assert that firewall1 and firewall2 are not equivalent
s.add(Not(firewall1 == firewall2))

# Check satisfiability and print the model
if s.check() == sat:
    print("SAT")
    print(s.model())
else:
    print("UNSAT")

'''
import ipaddress

class AddressRange:
    def __init__(self, low, high):
        self.low = ipaddress.IPv4Address(low)
        self.high = ipaddress.IPv4Address(high)

class AddressSet:
    def __init__(self, contains_all=False, ranges=None):
        self.contains_all = contains_all
        self.ranges = ranges or []

class PortRange:
    def __init__(self, low, high):
        self.low = int(low)
        self.high = int(high)

class PortSet:
    def __init__(self, contains_all=False, ranges=None):
        self.contains_all = contains_all
        self.ranges = ranges or []

class NetworkProtocol:
    def __init__(self, any_protocol=False, protocol_number=None):
        self.any = any_protocol
        self.protocol_number = protocol_number

class WindowsFirewallRule:
    def __init__(self, name, local_ports, remote_addresses, remote_ports, protocol, enabled, allow):
        self.name = name
        self.local_ports = local_ports
        self.remote_addresses = remote_addresses
        self.remote_ports = remote_ports
        self.protocol = protocol
        self.enabled = enabled
        self.allow = allow

def parse_address_set(text):
    text = text.strip()
    if text == "Any":
        return AddressSet(contains_all=True)
    
    ranges = []
    for part in text.split(','):
        part = part.strip()
        if '-' in part:
            low, high = part.split('-')
            ranges.append(AddressRange(low.strip(), high.strip()))
        else:
            ip = part.strip()
            ranges.append(AddressRange(ip, ip))
    
    return AddressSet(contains_all=False, ranges=ranges)

def parse_port_set(text):
    text = text.strip()
    if not text:
        raise ValueError("Port is empty")
    if text == "Any":
        return PortSet(contains_all=True)

    macros = {"RPC Endpoint Mapper", "RPC Dynamic Ports", "IPHTTPS", "Edge Traversal", "PlayTo Discovery"}
    if text in macros:
        raise ValueError(f"Unsupported port macro: {text}")

    ranges = []
    for part in text.split(','):
        part = part.strip()
        if '-' in part:
            low, high = part.split('-')
            ranges.append(PortRange(low.strip(), high.strip()))
        else:
            ranges.append(PortRange(part, part))
    
    return PortSet(contains_all=False, ranges=ranges)

def parse_protocol(text):
    text = text.strip()
    if text == "Any":
        return NetworkProtocol(any_protocol=True)
    
    try:
        protocol_number = int(text)
    except ValueError:
        proto_map = {"TCP": 6, "UDP": 17}
        if text.upper() not in proto_map:
            raise ValueError(f"Unknown protocol: {text}")
        protocol_number = proto_map[text.upper()]
    
    return NetworkProtocol(any_protocol=False, protocol_number=protocol_number)

def parse_rule_line(header_index, line, separator):
    fields = [f.strip() for f in line.split(separator)]
    
    return WindowsFirewallRule(
        name=fields[header_index["Name"]],
        local_ports=parse_port_set(fields[header_index["Local Port"]]),
        remote_addresses=parse_address_set(fields[header_index["Remote Address"]]),
        remote_ports=parse_port_set(fields[header_index["Remote Port"]]),
        protocol=parse_protocol(fields[header_index["Protocol"]]),
        enabled=fields[header_index["Enabled"]].strip() == "Yes",
        allow=fields[header_index["Action"]].strip() == "Allow"
    )

def parse_firewall_dump(text, separator='\t'):
    lines = text.strip().split('\n')
    headers = [h.strip() for h in lines[0].split(separator)]
    header_index = {h: i for i, h in enumerate(headers)}
    required = {"Name", "Enabled", "Action", "Local Port", "Remote Address", "Remote Port", "Protocol"}
    missing = required - header_index.keys()
    if missing:
        raise ValueError(f"Missing headers: {', '.join(missing)}")
    
    rules = []
    for i, line in enumerate(lines[1:]):
        if not line.strip():
            continue
        try:
            rule = parse_rule_line(header_index, line, separator)
            rules.append(rule)
        except Exception as e:
            print(f"Skipping line {i + 2}: {e}")
    
    return rules






from z3 import *

# Define symbolic traffic fields
src_ip = BitVec('src_ip', 32)
dst_ip = BitVec('dst_ip', 32)
src_port = BitVec('src_port', 16)
dst_port = BitVec('dst_port', 16)
protocol = BitVec('protocol', 8)


def ip_to_int(ip_str):
    import ipaddress
    return int(ipaddress.IPv4Address(ip_str))

def match_rule(rule):
    clauses = []

    # Protocol check
    if not rule.protocol.any:
        clauses.append(protocol == rule.protocol.protocol_number)

    # Remote address check
    if not rule.remote_addresses.contains_all:
        ip_clauses = []
        for r in rule.remote_addresses.ranges:
            low = ip_to_int(r.low)
            high = ip_to_int(r.high)
            ip_clauses.append(And(dst_ip >= low, dst_ip <= high))
        clauses.append(Or(*ip_clauses))

    # Remote port check
    if not rule.remote_ports.contains_all:
        port_clauses = []
        for r in rule.remote_ports.ranges:
            port_clauses.append(And(dst_port >= r.low, dst_port <= r.high))
        clauses.append(Or(*port_clauses))

    # Local port check
    if not rule.local_ports.contains_all:
        local_port_clauses = []
        for r in rule.local_ports.ranges:
            local_port_clauses.append(And(src_port >= r.low, src_port <= r.high))
        clauses.append(Or(*local_port_clauses))

    # Combine all rule checks
    return And(*clauses)

def build_firewall_policy(rules):
    for rule in rules:
        if not rule.enabled:
            continue
        match = match_rule(rule)
        yield (match, rule.allow)

def firewall_decision(rules):
    """
    Returns Z3 expression that determines if traffic is allowed by rule set.
    Follows first-match semantics.
    """
    policy = build_firewall_policy(rules)
    result = False
    for match, allow in policy:
        result = If(match, allow, result)
    return result

s = Solver()

# Define policies
decision1 = firewall_decision(rules1)
decision2 = firewall_decision(rules2)

# Ask if there's any traffic that is treated differently
s.add(decision1 != decision2)

if s.check() == sat:
    model = s.model()
    print("Found traffic that is treated differently:")
    print(f"src_port = {model[src_port]}")
    print(f"dst_port = {model[dst_port]}")
    print(f"dst_ip = {model[dst_ip]}")
    print(f"protocol = {model[protocol]}")
else:
    print("The two rule sets are equivalent.")

'''