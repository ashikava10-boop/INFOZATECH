
import socket

target = "127.0.0.1"

ports = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    135: "Windows RPC",
    443: "HTTPS",
    445: "Windows SMB",
    3306: "MySQL",
    3389: "Remote Desktop"
}

print("LOCAL NETWORK PORT SCANNER")
print("Target:", target)
print("-" * 35)

for port, service in ports.items():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            print("Port", port, "OPEN -", service)
        else:
            print("Port", port, "CLOSED -", service)

    except OSError as error:
        print("Error checking port", port, ":", error)

    finally:
        sock.close()

print("-" * 35)
print("Scan completed.")
print("Only scan systems you own or have permission to test.")
