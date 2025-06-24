# 🔍 Sniffer de paquets IP/TCP/UDP (Python - Raw Sockets)

import socket
import struct
import sys

# -----------------------------
# Fonction : conversion d'une adresse IP binaire en format lisible
# -----------------------------
def ip_format(addr_bytes):
    return '.'.join(map(str, addr_bytes))


# -----------------------------
# Fonction : conversion du protocole en texte lisible
# -----------------------------
def get_protocol_name(proto_num):
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto_num, f"Inconnu ({proto_num})")

# -----------------------------
# Fonction principale de sniffing
# -----------------------------
def sniff():
    try:
        # Création du socket brut (AF_PACKET pour Linux, mode promiscuous)
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        # Interface réseau active à surveiller (ex: wlo2 sur ta machine)
        sniffer.bind(("wlo2", 0))

        print(f"📡 Sniffing sur l'interface : wlo2 (Ctrl+C pour quitter)\n")

        while True:
            raw_data, addr = sniffer.recvfrom(65565)

            # Extraction de l'en-tête IP (après l'en-tête Ethernet de 14 octets)
            ip_header = raw_data[14:34]
            unpacked = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = unpacked[0]
            ihl = (version_ihl & 0xF) * 4
            protocol = unpacked[6]
            src_ip = socket.inet_ntoa(unpacked[8])
            dst_ip = socket.inet_ntoa(unpacked[9])
            proto_name = get_protocol_name(protocol)

            # Ports TCP/UDP (en-tête après l'en-tête IP)
            src_port = dst_port = None
            if protocol in (6, 17):
                tcp_udp_header = raw_data[14 + ihl:14 + ihl + 4]
                if len(tcp_udp_header) == 4:
                    src_port, dst_port = struct.unpack('!HH', tcp_udp_header)

            # Affichage
            if src_port and dst_port:
                print(f"📦 {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocole : {proto_name}")
            else:
                print(f"📦 {src_ip} -> {dst_ip} | Protocole : {proto_name}")

    except KeyboardInterrupt:
        print("\n🛑 Sniffing arrêté par l'utilisateur.")
        sys.exit(0)
    except PermissionError:
        print("❌ Erreur : Ce script doit être exécuté avec sudo (privilèges root).")
        sys.exit(1)
        
# -----------------------------
# Lancement du script
# -----------------------------
if __name__ == '__main__':
    sniff()
