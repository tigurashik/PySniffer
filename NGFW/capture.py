import pymysql
from scapy.all import sniff, IP, TCP, UDP, Ether, conf
import threading
from config import DB_CONFIG
import traceback
import queue

pool_size = 10  # Размер пула соединений
connection_pool = queue.Queue(maxsize=pool_size)

def init_connection_pool():
    for _ in range(pool_size):
        connection = pymysql.connect(**DB_CONFIG)
        connection_pool.put(connection)

def get_connection():
    try:
        return connection_pool.get(block=True, timeout=5)
    except queue.Empty:
        print("[ERROR] Пул соединений пуст. Не удалось получить соединение.")
        return None

def release_connection(connection):
    if connection:
        connection_pool.put(connection)

def save_packet(packet):
    connection = None
    try:
        connection = get_connection()
        if connection is None:
            return

        cursor = connection.cursor()

        src_mac = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "Unknown"

        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        src_port = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else "N/A")
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else "N/A")

        protocol_num = packet[IP].proto if packet.haslayer(IP) else None
        protocol = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol_num, f"Unknown ({protocol_num})") if protocol_num is not None else "Other"

        length = len(packet)
        raw_data = str(packet)

        query = """
        INSERT INTO packets (src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, length, raw_data)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, length, raw_data))
        connection.commit()

        print(f"[SAVED] MAC {src_mac} -> {dst_mac}, IP {src_ip} -> {dst_ip}, "
              f"Порты {src_port} -> {dst_port}, Протокол: {protocol}, Длина: {length}")
    except pymysql.MySQLError as e:
        print(f"[ERROR] Ошибка при сохранении пакета: {e}")
        traceback.print_exc()
    except Exception as e:
        print(f"[ERROR] Общая ошибка: {e}")
        traceback.print_exc()
        print(f"[PACKET] {str(packet)}")
    finally:
        if connection:
            release_connection(connection)

def capture_traffic(interface):
    print(f"Начало захвата трафика на интерфейсе {interface}...")
    sniff(prn=save_packet, iface=interface, filter="", store=0)

def start_sniffing_on_all_interfaces():
    interfaces = conf.ifaces.data.keys()
    threads = []

    for interface in interfaces:
        thread = threading.Thread(target=capture_traffic, args=(interface,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    init_connection_pool()
    start_sniffing_on_all_interfaces()
