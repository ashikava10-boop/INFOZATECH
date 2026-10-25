import socket

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "Windows RPC",
    143: "IMAP",
    443: "HTTPS",
    445: "Windows SMB",
    3306: "MySQL",
    3389: "Remote Desktop"
}

def scan_port(target, port, timeout=1):
    """Check whether a TCP port is open, closed, or unreachable."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

            if result == 0:
                return "OPEN"
            elif result == 10061:
                return "CLOSED"
            else:
                return "NOT CONFIRMED OPEN"

    except socket.timeout:
        return "TIMED OUT"
    except socket.gaierror:
        return "HOST NAME ERROR"
    except OSError as error:
        return "CONNECTION ERROR: " + str(error)

def main():
    print("=" * 45)
    print("   LOCAL NETWORK PORT SCANNER")
    print("=" * 45)
    print("Educational use only.")
    print("Scan only systems you own or have permission to test.\n")

    target = input(
        "Enter target IP (press Enter for your own computer): "
    ).strip()

    if target == "":
        target = "127.0.0.1"

    try:
        socket.inet_aton(target)
    except OSError:
        print("Invalid IPv4 address. Please run the program again.")
        return

    print("\nTarget:", target)
    print("-" * 45)
    print("Scanning common ports...\n")

    open_count = 0

    for port, service in PORTS.items():
        status = scan_port(target, port)

        print("Port", port, "-", status, "-", service)

        if status == "OPEN":
            open_count += 1

    print("\n" + "=" * 45)
    print("Scan completed.")
    print("Open ports found:", open_count)
    print("=" * 45)

    print("\nSECURITY SUMMARY")
    print("Open ports provide access to network services.")
    print("Unnecessary or insecure services may create")
    print("security risks. Check that each open service")
    print("is needed, updated, and properly protected.")
    print("Only scan systems you own or have permission to test.")

if __name__ == "__main__":
    main()
