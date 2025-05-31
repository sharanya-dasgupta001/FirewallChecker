import ipaddress
import argparse
import csv
from z3 import *
from typing import List, Dict, Generator, Optional

class AddressRange:
    def __init__(self, low: str, high: str):
        self.low = ipaddress.IPv4Address(low)
        self.high = ipaddress.IPv4Address(high)

class AddressSet:
    def __init__(self, contains_all: bool = False, ranges: Optional[List[AddressRange]] = None):
        self.contains_all = contains_all
        self.ranges = ranges or []

class PortRange:
    def __init__(self, low: int, high: int):
        self.low = low
        self.high = high

class PortSet:
    def __init__(self, contains_all: bool = False, ranges: Optional[List[PortRange]] = None):
        self.contains_all = contains_all
        self.ranges = ranges or []

class NetworkProtocol:
    def __init__(self, any_protocol: bool = False, protocol_number: int = 0):
        self.any = any_protocol
        self.protocol_number = protocol_number

    @staticmethod
    def try_get_protocol_number(name: str) -> Optional[int]:
        """Maps a protocol name (e.g., 'TCP') to its protocol number."""
        protocol_map = {
            "HOPOPT": 0,
            "ICMP": 1,
            "IGMP": 2,
            "TCP": 6,
            "UDP": 17,
            "IPv6": 41,
            "IPv6-Route": 43,
            "IPv6-Frag": 44,
            "GRE": 47,
            "ICMPv6": 58,
            "IPv6-NoNxt": 59,
            "IPv6-Opts": 60,
            "VRRP": 112,
            "PGM": 113,
            "L2TP": 115
        }
        return protocol_map.get(name.upper())

# Represents a single firewall rule
class WindowsFirewallRule:
    def __init__(self, name: str, remote_addresses: AddressSet, remote_ports: PortSet,
                 local_ports: PortSet, protocol: NetworkProtocol, enabled: bool, allow: bool):
        self.name = name
        self.remote_addresses = remote_addresses
        self.remote_ports = remote_ports
        self.local_ports = local_ports
        self.protocol = protocol
        self.enabled = enabled
        self.allow = allow

    def __str__(self):
        return (
            f"Rule: {self.name}\n"
            f"  Enabled: {self.enabled}, Action: {'Allow' if self.allow else 'Block'}\n"
            f"  Protocol: {'Any' if self.protocol.any else self.protocol.protocol_number}\n"
            f"  Local Ports: {'Any' if self.local_ports.contains_all else [(r.low, r.high) for r in self.local_ports.ranges]}\n"
            f"  Remote Ports: {'Any' if self.remote_ports.contains_all else [(r.low, r.high) for r in self.remote_ports.ranges]}\n"
            f"  Remote Addresses: {'Any' if self.remote_addresses.contains_all else [(str(r.low), str(r.high)) for r in self.remote_addresses.ranges]}"
        )

# Parses firewall rules from a file
class WindowsFirewallRuleParser:
    REQUIRED_HEADERS = [
        "Name", "Enabled", "Action", "Local Port",
        "Remote Address", "Remote Port", "Protocol"
    ]

    @staticmethod
    def parse(text: str, separator: str) -> Generator[WindowsFirewallRule, None, None]:
        """
        Parses text containing firewall rules separated by the given delimiter (e.g., '\t').
        """
        reader = csv.reader(text.strip().splitlines(), delimiter=separator)
        header_line = next(reader)
        header_index = WindowsFirewallRuleParser.parse_header(header_line)

        for i, line in enumerate(reader):
            try:
                yield WindowsFirewallRuleParser.parse_record(header_index, line)
            except Exception as e:
                print(f"Skipping line {i + 2} - {e}")

    @staticmethod
    def parse_header(header_line: List[str]) -> Dict[str, int]:
        """Validates headers and maps them to their column indices."""
        header_index = {h.strip(): i for i, h in enumerate(header_line)}
        missing = [h for h in WindowsFirewallRuleParser.REQUIRED_HEADERS if h not in header_index]
        if missing:
            raise ValueError(f"Missing required headers: {', '.join(missing)}")
        return header_index

    @staticmethod
    def parse_record(header_index: Dict[str, int], record: List[str]) -> WindowsFirewallRule:
        """Converts a row from the file into a WindowsFirewallRule object."""
        def get(field: str) -> str:
            return record[header_index[field]].strip()

        return WindowsFirewallRule(
            name=get("Name"),
            remote_addresses=WindowsFirewallRuleParser.parse_address_set(get("Remote Address")),
            remote_ports=WindowsFirewallRuleParser.parse_port_set(get("Remote Port")),
            local_ports=WindowsFirewallRuleParser.parse_port_set(get("Local Port")),
            protocol=WindowsFirewallRuleParser.parse_network_protocol(get("Protocol")),
            enabled=(get("Enabled") == "Yes"),
            allow=(get("Action") == "Allow")
        )

    @staticmethod
    def parse_address_set(text: str) -> AddressSet:
        if text == "Any":
            return AddressSet(contains_all=True)

        ranges = []
        for part in text.split(','):
            part = part.strip()
            if '-' in part:
                low, high = part.split('-')
                ranges.append(AddressRange(low.strip(), high.strip()))
            else:
                ranges.append(AddressRange(part, part))
        return AddressSet(contains_all=False, ranges=ranges)

    @staticmethod
    def parse_port_set(text: str) -> PortSet:
        """raises for unsupported macros."""
        if not text:
            raise ValueError("Port is empty")

        if text == "Any":
            return PortSet(contains_all=True)

        unsupported_macros = {
            "RPC Endpoint Mapper", "RPC Dynamic Ports",
            "IPHTTPS", "Edge Traversal", "PlayTo Discovery"
        }
        if text in unsupported_macros:
            raise ValueError(f"Unsupported port macro: {text}")

        ranges = []
        for part in text.split(','):
            part = part.strip()
            if '-' in part:
                low, high = part.split('-')
                ranges.append(PortRange(int(low.strip()), int(high.strip())))
            else:
                val = int(part)
                ranges.append(PortRange(val, val))
        return PortSet(contains_all=False, ranges=ranges)

    @staticmethod
    def parse_network_protocol(text: str) -> NetworkProtocol:
        """Parses the protocol field into a NetworkProtocol object"""
        if text == "Any":
            return NetworkProtocol(any_protocol=True)

        protocol_number = NetworkProtocol.try_get_protocol_number(text)
        if protocol_number is None:
            protocol_number = int(text)

        return NetworkProtocol(any_protocol=False, protocol_number=protocol_number)

class FirewallEquivalenceChecker:
    def __init__(self, rules1, rules2, block_by_default=True):
        self.rules1 = rules1
        self.rules2 = rules2
        self.block_by_default = block_by_default

    def allows(self, rules, packet):
        """
        Builds a Z3 expression that represents whether the given packet is allowed by the firewall.
        """
        block_exprs = []
        allow_exprs = []

        for rule in rules:
            if not rule.enabled:
                continue

            proto_cond = BoolVal(True) if rule.protocol.any else packet['protocol'] == rule.protocol.protocol_number
            local_port_cond = self.port_set_expr(packet['local_port'], rule.local_ports)
            remote_port_cond = self.port_set_expr(packet['remote_port'], rule.remote_ports)
            remote_addr_cond = self.address_set_expr(packet['remote_ip'], rule.remote_addresses)

            match_expr = And(proto_cond, local_port_cond, remote_port_cond, remote_addr_cond)

            if rule.allow:
                allow_exprs.append(match_expr)
            else:
                block_exprs.append(match_expr)

        has_block = Or(*block_exprs) if block_exprs else BoolVal(False)
        has_allow = Or(*allow_exprs) if allow_exprs else BoolVal(False)

        if not self.block_by_default:
            return Not(has_block)
        else:
            return And(has_allow, Not(has_block))

    def port_set_expr(self, port_var, port_set):
        """Returns Z3 expression checking if port_var is in the given PortSet."""
        if port_set.contains_all:
            return BoolVal(True)
        return Or([And(port_var >= r.low, port_var <= r.high) for r in port_set.ranges])

    def address_set_expr(self, ip_var, addr_set):
        """Returns Z3 expression checking if ip_var is in the given AddressSet."""
        if addr_set.contains_all:
            return BoolVal(True)
        return Or([
            And(ip_var >= self.ip_to_int(r.low), ip_var <= self.ip_to_int(r.high))
            for r in addr_set.ranges
        ])

    def ip_to_int(self, ip):
        """Converts IPv4 address to integer."""
        return int(ip)

    def packet_from_model(self, model, packet_vars):
        """Extracts concrete packet values from a Z3 model."""
        packet_values = {}
        packet_values_constraint = {}
        for k, v in packet_vars.items():
            if model[v] is not None :
                val = model.eval(v, model_completion=True)
                if k == 'remote_ip':
                    try:
                        packet_values_constraint[k] = val
                        packet_values[k] = str(ipaddress.IPv4Address(val.as_long()))
                    except Exception:
                        packet_values[k] = "Any"
                else:
                    packet_values_constraint[k] = val
                    packet_values[k] = val.as_long() if hasattr(val, 'as_long') else val
            else :
                packet_values[k] = "Any"
        return packet_values, packet_values_constraint

    def rules_matching_packet(self, rules, packet_values):
        """
        Returns list of rule names that match the given packet (with concrete values).
        """
        matched_rules = []
        for rule in rules:
            if not rule.enabled:
                continue

            if not self.rule_matches_packet(rule, packet_values):
                continue

            action = "Allow" if rule.allow else "Block"
            matched_rules.append((rule.name if hasattr(rule, 'name') else "UnnamedRule", action))
        return matched_rules

    def rule_matches_packet(self, rule, packet_values):
        """Checks if a single rule matches the packet (all fields concrete)."""
        def port_in_set(port, port_set):
            if port == "Any":
                return True
            for r in port_set.ranges:
                if r.low <= port <= r.high:
                    return True
            return port_set.contains_all

        def addr_in_set(ip_str, addr_set):
            if ip_str == "Any":
                return True
            ip_int = int(ipaddress.IPv4Address(ip_str))
            for r in addr_set.ranges:
                low_int = int(r.low)
                high_int = int(r.high)
                if low_int <= ip_int <= high_int:
                    return True
            return addr_set.contains_all

        # Protocol match
        if not rule.protocol.any:
            if packet_values['protocol'] != "Any" and packet_values['protocol'] != rule.protocol.protocol_number:
                return False

        # Ports
        if not port_in_set(packet_values['local_port'], rule.local_ports):
            return False
        if not port_in_set(packet_values['remote_port'], rule.remote_ports):
            return False

        # Addresses
        if not addr_in_set(packet_values['remote_ip'], rule.remote_addresses):
            return False

        return True
    

    def check_equivalence(self, max_counterexamples=10):
        """Uses Z3 to check equivalence of two firewall rule sets."""
        s = Solver()
        packet = {
            'protocol': Int('proto'),
            'local_port': Int('lport'),
            'remote_port': Int('rport'),
            'remote_ip': Int('rip')
        }

        f1_allows = self.allows(self.rules1, packet)
        f2_allows = self.allows(self.rules2, packet)

        s.add(f1_allows != f2_allows)
        s.add(packet['local_port'] >= 0, packet['local_port'] <= 65535)
        s.add(packet['remote_port'] >= 0, packet['remote_port'] <= 65535)
        s.add(packet['protocol'] >= 0, packet['protocol'] <= 255)
        s.add(packet['remote_ip'] >= 0, packet['remote_ip'] <= 2**32 - 1)


        found = 0
        print("-" * 94)
        if s.check() == sat:
            print("\n❌ Firewalls are NOT equivalent.\n")
            print("-" * 94)
        
        counter_examples = []
        while found < max_counterexamples and s.check() == sat:
            m = s.model()
            pkt_vals, pkt_vals_const = self.packet_from_model(m, packet)

            f1_allowed = is_true(m.eval(f1_allows, model_completion=True))
            f2_allowed = is_true(m.eval(f2_allows, model_completion=True))


            f1_matching_rules = self.rules_matching_packet(self.rules1, pkt_vals)
            f2_matching_rules = self.rules_matching_packet(self.rules2, pkt_vals)

            print(f"Packet #{found+1}:")
            for k, v in pkt_vals.items():
                if k == 'protocol':
                    reversed_protocol_map = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 112: "VRRP", 113: "PGM", 115: "L2TP"}
                    v = reversed_protocol_map.get(v, v)  

                print(f"  {k}: {v}")
            
            print("\nFirewall 1 allows" if f1_allowed else "\nFirewall 1 blocks", end = " & ")
            print("Firewall 2 allows" if f2_allowed else "Firewall 2 blocks")
            print("-" * 94)

            # Block this solution for next iteration
            block_current = []
            for k,v in pkt_vals_const.items():
                block_current.append(packet[k] != v)
            s.add(Or(block_current))

            found += 1
            counter_examples.append((f1_matching_rules, f2_matching_rules))

        if found == 0:
            print("✅ Firewalls are equivalent.")

        if len(counter_examples) > 0:
            print("\n\nFirewall rules matching counter example packets:")
            print("-" * 94)
            print(f"| {'Packet':^7} | {'Firewall':^8} | {'Action':^6} | {'Rule Name':<60} |")
            print("-" * 94)
            for idx, ce in enumerate(counter_examples):
                for rule in ce[0]:
                    print(f"| {idx+1:^7} | {'1':^8} | {rule[-1]:^6} | {rule[0][:50]:<60} |")
                for rule in ce[1]:
                    print(f"| {idx+1:^7} | {'2':^8} | {rule[-1]:^6} | {rule[0][:50]:<60} |")
            print("-" * 94)



if __name__ == '__main__':
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Compare two Windows firewall configurations for equivalence.")
    parser.add_argument('--firewall1', required=True, help='Path to the first firewall rule file')
    parser.add_argument('--firewall2', required=True, help='Path to the second firewall rule file')
    parser.add_argument('--separator', default='\t', help='Field separator in the files (default: tab)')
    parser.add_argument('--max-counterexamples', type=int, default=10, help='Maximum number of counterexamples to display')

    args = parser.parse_args()

    # Parse rules from files
    with open(args.firewall1, 'r') as f1:
        rules1 = list(WindowsFirewallRuleParser.parse(f1.read(), args.separator))
    with open(args.firewall2, 'r') as f2:
        rules2 = list(WindowsFirewallRuleParser.parse(f2.read(), args.separator))

    # Run equivalence checker
    checker = FirewallEquivalenceChecker(rules1, rules2)
    checker.check_equivalence(max_counterexamples=args.max_counterexamples)