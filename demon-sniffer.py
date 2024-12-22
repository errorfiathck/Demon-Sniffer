import ipaddress
import os
import socket
import struct
import sys
import argparse
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QPushButton,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QDialog,
    QTextEdit,
)
import binascii  # For binary and hex conversion


class IP:
    def __init__(self, buff=None):
        header = struct.unpack("<BBHHHBBH4s4s", buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constant to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print("%s No protocol for %s" % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)


class ICMP:
    def __init__(self, buff):
        header = struct.unpack("<BBH", buff[:4])
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.data = buff[4:]


def sniff(host, callback):
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))

    # include the IP header in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # read packets
            raw_buffer = sniffer.recvfrom(65535)[0]
            # create an IP header from the first 20 bytes
            ip_header = IP(raw_buffer[0:20])

            icmp_type = "N/A"
            icmp_code = "N/A"
            icmp_seq = "N/A"

            if ip_header.protocol == "ICMP":
                icmp_header = ICMP(raw_buffer[20:28])
                icmp_type = icmp_header.type
                icmp_code = icmp_header.code

                # Extract the ICMP sequence number (if present)
                if len(raw_buffer) > 28:
                    icmp_seq = struct.unpack("!H", raw_buffer[28:30])[0]

            packet_length = len(raw_buffer)

            # Pass the information to the callback
            callback(
                ip_header.protocol,
                ip_header.src_address,
                ip_header.dst_address,
                icmp_type,
                icmp_code,
                icmp_seq,
                ip_header.ttl,
                ip_header.id,
                packet_length,
                raw_buffer,  # Pass the raw_buffer here
            )

    except KeyboardInterrupt:
        # if were on Windows, turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


class PacketDetailsWindow(QDialog):
    def __init__(
        self, protocol, src, dst, icmp_type, icmp_code, ttl, packet_id, raw_buffer
    ):
        super().__init__()
        self.setWindowTitle("Packet Details")
        self.setGeometry(200, 200, 600, 400)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Connection information
        self.info_label = QLabel(
            f"""
        <b>Connection Details:</b><br>
        Protocol: {protocol}<br>
        Source: {src}<br>
        Destination: {dst}<br>
        ICMP Type: {icmp_type}<br>
        ICMP Code: {icmp_code}<br>
        TTL: {ttl}<br>
        Packet ID: {packet_id}
        """
        )
        self.layout.addWidget(self.info_label)

        # Binary and Hex views
        self.binary_view = QTextEdit()
        self.binary_view.setReadOnly(True)
        self.binary_view.setLineWrapMode(QTextEdit.NoWrap)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QTextEdit.NoWrap)

        self.binary_view.setText(self.format_binary(raw_buffer))
        self.hex_view.setText(self.format_hex(raw_buffer))

        self.layout.addWidget(QLabel("<b>Binary Data:</b>"))
        self.layout.addWidget(self.binary_view)

        self.layout.addWidget(QLabel("<b>Hex Data:</b>"))
        self.layout.addWidget(self.hex_view)

    def format_binary(self, data):
        """Converts raw data into a binary string representation."""
        binary_data = " ".join(format(byte, "08b") for byte in data)
        return binary_data

    def format_hex(self, data):
        """Converts raw data into a hex string representation."""
        hex_data = binascii.hexlify(data).decode("utf-8")
        return " ".join(hex_data[i : i + 2] for i in range(0, len(hex_data), 2))


from PyQt5.QtWidgets import QCheckBox, QTabWidget


class PacketSnifferApp(QMainWindow):
    def __init__(self, default_host=""):
        super().__init__()

        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 1000, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        # Input for host
        self.host_input_layout = QHBoxLayout()
        self.host_label = QLabel("Host:")
        self.host_input = QLineEdit()
        self.host_input.setText(default_host)
        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.host_input_layout.addWidget(self.host_label)
        self.host_input_layout.addWidget(self.host_input)
        self.host_input_layout.addWidget(self.start_button)
        self.host_input_layout.addWidget(self.stop_button)
        self.layout.addLayout(self.host_input_layout)

        # Tabs for display management
        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget)

        # Packet table tab
        self.packet_table_tab = QWidget()
        self.packet_table_layout = QVBoxLayout()
        self.packet_table_tab.setLayout(self.packet_table_layout)
        self.tab_widget.addTab(self.packet_table_tab, "Packets")

        # Table for packet display
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(
            [
                "Protocol",
                "Source",
                "Destination",
                "ICMP Type",
                "ICMP Code",
                "ICMP Seq",
                "TTL",
                "ID",
                "Length",
            ]
        )
        self.table.cellDoubleClicked.connect(self.show_packet_details)
        self.packet_table_layout.addWidget(self.table)

        # View options tab
        self.view_options_tab = QWidget()
        self.view_options_layout = QVBoxLayout()
        self.view_options_tab.setLayout(self.view_options_layout)
        self.tab_widget.addTab(self.view_options_tab, "View Options")

        # Checkboxes for toggling column visibility
        self.column_checkboxes = []
        for col in range(self.table.columnCount()):
            label = self.table.horizontalHeaderItem(col).text()
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(lambda state, col=col: self.toggle_column(col, state))
            self.column_checkboxes.append(checkbox)
            self.view_options_layout.addWidget(checkbox)


        # Store raw packet data for detailed view
        self.packet_data = []
        self.sniffing_thread = None
        self.sniffing_active = False

    def start_sniffing(self):
        if self.sniffing_active:
            QMessageBox.warning(self, "Warning", "Sniffing is already running.")
            return

        host = self.host_input.text()
        if not host:
            QMessageBox.warning(self, "Error", "Please enter a valid host IP address.")
            return

        self.sniffing_active = True

        def callback(
            protocol,
            src,
            dst,
            icmp_type,
            icmp_code,
            icmp_seq,
            ttl,
            packet_id,
            packet_length,
            raw_buffer,
        ):
            self.add_packet(
                protocol,
                src,
                dst,
                icmp_type,
                icmp_code,
                icmp_seq,
                ttl,
                packet_id,
                packet_length,
                raw_buffer,
            )

        # Run sniffing in a separate thread
        import threading

        self.sniffing_thread = threading.Thread(target=sniff, args=(host, callback), daemon=True)
        self.sniffing_thread.start()
        QMessageBox.information(
            self, "Sniffing Started", f"Started sniffing on host: {host}"
        )

    def stop_sniffing(self):
        if not self.sniffing_active:
            QMessageBox.warning(self, "Warning", "Sniffing is not running.")
            return

        self.sniffing_active = False
        QMessageBox.information(self, "Sniffing Stopped", "Packet sniffing has been stopped.")

    def add_packet(
        self,
        protocol,
        src,
        dst,
        icmp_type,
        icmp_code,
        icmp_seq,
        ttl,
        packet_id,
        packet_length,
        raw_buffer,
    ):
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        self.table.setItem(row_position, 0, QTableWidgetItem(str(protocol)))
        self.table.setItem(row_position, 1, QTableWidgetItem(str(src)))
        self.table.setItem(row_position, 2, QTableWidgetItem(str(dst)))
        self.table.setItem(row_position, 3, QTableWidgetItem(str(icmp_type)))
        self.table.setItem(row_position, 4, QTableWidgetItem(str(icmp_code)))
        self.table.setItem(row_position, 5, QTableWidgetItem(str(icmp_seq)))
        self.table.setItem(row_position, 6, QTableWidgetItem(str(ttl)))
        self.table.setItem(row_position, 7, QTableWidgetItem(str(packet_id)))
        self.table.setItem(row_position, 8, QTableWidgetItem(str(packet_length)))

        # Store raw packet data for detailed view
        self.packet_data.append(
            (protocol, src, dst, icmp_type, icmp_code, ttl, packet_id, raw_buffer)
        )

    def show_packet_details(self, row, column):
        # Get the raw packet data for the selected row
        packet_info = self.packet_data[row]

        protocol, src, dst, icmp_type, icmp_code, ttl, packet_id, raw_buffer = (
            packet_info
        )

        # Open the Packet Details Window
        details_window = PacketDetailsWindow(
            protocol, src, dst, icmp_type, icmp_code, ttl, packet_id, raw_buffer
        )
        details_window.exec_()

    def toggle_column(self, col, state):
        self.table.setColumnHidden(col, state == 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer with Optional GUI")
    parser.add_argument(
        "-A", action="store_true", help="Launch the graphical environment"
    )
    parser.add_argument(
        "-host", type=str, help="Specify the host IP address", default=""
    )
    parser.add_argument(
        "-details", action="store_true", help="View detailed packet information in the CLI"
    )
    args = parser.parse_args()

    if args.A:
        app = QApplication(sys.argv)
        main_window = PacketSnifferApp(default_host=args.host)
        main_window.show()
        sys.exit(app.exec_())
    elif args.host:
        def callback(
            protocol,
            src,
            dst,
            icmp_type,
            icmp_code,
            icmp_seq,
            ttl,
            packet_id,
            packet_length,
            raw_buffer,
        ):
            if args.details:
                # Detailed CLI output
                print("\n[Packet Captured]")
                print(f"Protocol: {protocol}")
                print(f"Source: {src}")
                print(f"Destination: {dst}")
                print(f"ICMP Type: {icmp_type}")
                print(f"ICMP Code: {icmp_code}")
                print(f"ICMP Seq: {icmp_seq}")
                print(f"TTL: {ttl}")
                print(f"Packet ID: {packet_id}")
                print(f"Length: {packet_length}")
                print(f"Raw Buffer: {binascii.hexlify(raw_buffer).decode()}\n")
                print("-" * 60)
            else:
                # Basic CLI output
                print(
                    f"Protocol: {protocol}, Source: {src}, Destination: {dst}, ICMP Type: {icmp_type}, "
                    f"ICMP Code: {icmp_code}, ICMP Seq: {icmp_seq}, TTL: {ttl}, ID: {packet_id}, Length: {packet_length}"
                )

        sniff(args.host, callback)
    else:
        print(
            "Please use the -A flag to launch the graphical interface, -cli for detailed CLI output, "
            "or specify a host with -host."
        )
