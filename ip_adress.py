from z3 import *

# Create 32-bit bit vector for IP address
ip_address = BitVec('ip_address', 32)

# Create 16-bit bit vector for port number
port_number = BitVec('port_number', 16)

# Set the values for IP address and port number
ip_value = 203 << 24 | 0 << 16 | 113 << 8 | 5  # Equivalent to 203.0.113.5
port_value = 80  # Port 80

# Create a solver
solver = Solver()

# Assert the values of the IP and port
solver.add(ip_address == ip_value)
solver.add(port_number == port_value)

# Check satisfiability
if solver.check() == sat:
    model = solver.model()
    # Get the values of the IP and port
    print(f"IP Address: {model[ip_address]}")
    print(f"Port Number: {model[port_number]}")
else:
    print("UNSAT")
