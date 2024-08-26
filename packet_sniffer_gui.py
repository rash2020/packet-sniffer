import tkinter as tk
from tkinter import ttk, messagebox, filedialog, colorchooser
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, AsyncSniffer, Raw, wrpcap, rdpcap
import os
import sys
import threading
import netifaces

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.set_window_position(1000, 600)
        self.root.minsize(800, 600)

        # Detect available interfaces (move this before setup_ui())
        self.interfaces = netifaces.interfaces()
        self.selected_interface = tk.StringVar()
        if 'en0' in self.interfaces:
            self.selected_interface.set('en0')  # Set default to 'en0'
        else:
            self.selected_interface.set(self.interfaces[0])  # Default to the first interface

        self.create_menu()
        self.setup_ui()

        self.sniffer = None
        self.sniffing = False
        self.packets = []
        self.filtered_packets = []
        self.check_privileges()

    def setup_ui(self):
        root = self.root
        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)

        # Interface selection dropdown
        interface_label = tk.Label(root, text="Select Interface:")
        interface_label.grid(row=0, column=0, padx=10, pady=10)

        self.interface_combobox = ttk.Combobox(root, textvariable=self.selected_interface)
        self.interface_combobox['values'] = self.interfaces
        self.interface_combobox.grid(row=0, column=1, padx=10, pady=10)

        # Table for displaying packets with a scrollbar
        self.table_frame = ttk.Frame(root)
        self.table_frame.grid(row=1, column=0, columnspan=6, sticky="nsew")
        self.tree = ttk.Treeview(self.table_frame, columns=("Source", "Destination", "Protocol", "Length", "Info"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Protocol Filter
        self.protocol_filter = tk.StringVar()
        self.protocol_combobox = ttk.Combobox(root, textvariable=self.protocol_filter)
        self.protocol_combobox['values'] = ("All", "TCP", "UDP", "ICMP", "DNS", "ARP", "FTP", "SMTP", "HTTP", "HTTPS", "SSL/TLS", "SSH", "Telnet")
        self.protocol_combobox.current(0)
        self.protocol_combobox.grid(row=0, column=2, padx=10, pady=10)
        self.protocol_combobox.bind("<<ComboboxSelected>>", self.filter_packets)

        # Buttons
        self.button_frame = ttk.Frame(root)
        self.button_frame.grid(row=2, column=0, columnspan=6, pady=10, sticky="ew")

        self.start_button = tk.Button(self.button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)

        self.save_button = tk.Button(self.button_frame, text="Save Packets to File", command=self.save_packets)
        self.save_button.grid(row=0, column=2, padx=5, pady=5)

        self.load_button = tk.Button(self.button_frame, text="Load Packets from File", command=self.load_packets)
        self.load_button.grid(row=0, column=3, padx=5, pady=5)

        self.details_button = tk.Button(self.button_frame, text="View Packet Details", command=self.view_packet_details)
        self.details_button.grid(row=0, column=4, padx=5, pady=5)

        self.stats_button = tk.Button(self.button_frame, text="View Statistics", command=self.view_statistics)
        self.stats_button.grid(row=0, column=5, padx=5, pady=5)

    def set_window_position(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)
        theme_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Change Background Color", command=self.change_bg_color)

        view_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Select Columns", command=self.select_columns)

    def change_bg_color(self):
        color = colorchooser.askcolor()[1]
        if color:
            self.root.config(bg=color)

    def select_columns(self):
        column_selection_window = tk.Toplevel(self.root)
        column_selection_window.title("Select Columns")

        options = [("Source", "Source"), ("Destination", "Destination"), ("Protocol", "Protocol"), ("Length", "Length"), ("Info", "Info")]
        self.column_vars = {name: tk.BooleanVar(value=True) for name, display_name in options}

        for name, display_name in options:
            checkbox = tk.Checkbutton(column_selection_window, text=display_name, variable=self.column_vars[name], command=self.update_columns)
            checkbox.pack(anchor=tk.W)

    def update_columns(self):
        visible_columns = [column for column, var in self.column_vars.items() if var.get()]
        self.tree.config(displaycolumns=visible_columns)

    def check_privileges(self):
        if os.name != 'nt' and os.geteuid() != 0:
            messagebox.showerror("Permissions Error", "You must run this program as root or with elevated privileges.")
            sys.exit(1)

    def start_sniffing(self):
        selected_iface = self.selected_interface.get()
        if selected_iface not in netifaces.interfaces():
            messagebox.showerror("Error", f"Selected interface {selected_iface} is not available.")
            return

        try:
            self.sniffer = AsyncSniffer(prn=self.process_packet, iface=selected_iface)
            self.sniffer.start()
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.tree.delete(*self.tree.get_children())
            self.packets = []
            self.filtered_packets = []
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start sniffer on {selected_iface}: {e}")

    def stop_sniffing(self):
        def stop_sniffing_thread():
            try:
                self.sniffing = False
                if self.sniffer:
                    self.sniffer.stop()
                    self.sniffer.join(timeout=10)
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while stopping the sniffer: {str(e)}")
            finally:
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.filter_packets()  # Ensure filter is applied after stopping

        threading.Thread(target=stop_sniffing_thread).start()

    def process_packet(self, packet):
        if IP in packet or ARP in packet:
            self.packets.append(packet)
            if self.protocol_filter.get() == "All" or self.get_protocol_name(packet) == self.protocol_filter.get():
                self.filtered_packets.append(packet)
                # Update display on the main thread
                self.root.after(0, self.update_display, [packet])

    def get_protocol_name(self, packet):
        if ARP in packet:
            return "ARP"
        elif DNS in packet:
            return "DNS"
        elif TCP in packet:
            if packet[TCP].sport == 21 or packet[TCP].dport == 21:
                return "FTP"
            elif packet[TCP].sport == 25 or packet[TCP].dport == 25:
                return "SMTP"
            elif packet[TCP].sport == 80 or packet[TCP].dport == 80:
                return "HTTP"
            elif packet[TCP].sport == 443 or packet[TCP].dport == 443:
                return "HTTPS"
            elif packet[TCP].sport == 22 or packet[TCP].dport == 22:
                return "SSH"
            elif packet[TCP].sport == 23 or packet[TCP].dport == 23:
                return "Telnet"
            elif packet[TCP].sport in [443, 8443] or packet[TCP].dport in [443, 8443]:
                return "SSL/TLS"
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        else:
            return f"Other ({packet[IP].proto})"

    def filter_packets(self, event=None):
        self.filtered_packets = []
        filter_protocol = self.protocol_filter.get()
        for packet in self.packets:
            protocol_name = self.get_protocol_name(packet)
            if filter_protocol == "All" or filter_protocol == protocol_name:
                self.filtered_packets.append(packet)
        self.update_display()

    def update_display(self, packets=None):
        if packets is None:
            packets = self.filtered_packets
            self.tree.delete(*self.tree.get_children())

        for packet in packets:
            src_ip = packet[IP].src if IP in packet else "N/A"
            dst_ip = packet[IP].dst if IP in packet else "N/A"
            length = len(packet)

            protocol_name = self.get_protocol_name(packet)
            info = self.get_packet_info(packet)
            self.tree.insert("", "end", values=(src_ip, dst_ip, protocol_name, length, info))

    def get_packet_info(self, packet):
        if ARP in packet:
            return f"ARP - {packet[ARP].psrc} -> {packet[ARP].pdst}"
        elif DNS in packet:
            if packet[DNS].qr == 0:  # DNS Query
                if DNSQR in packet:
                    return f"DNS Query: {packet[DNSQR].qname.decode()}"
                else:
                    return "DNS Query: No query name found"
            else:  # DNS Response
                if DNSRR in packet:
                    return f"DNS Response: {packet[DNSRR].rdata}"
                else:
                    return "DNS Response: No response data found"
        elif TCP in packet:
            if Raw in packet:
                raw_payload = packet[Raw].load.decode(errors='ignore')
                if packet[TCP].sport == 21 or packet[TCP].dport == 21:  # FTP
                    return f"FTP Data: {raw_payload[:50]}"
                elif packet[TCP].sport == 25 or packet[TCP].dport == 25:  # SMTP
                    return f"SMTP Data: {raw_payload[:50]}"
                elif packet[TCP].sport in [443, 8443] or packet[TCP].dport in [443, 8443]:  # SSL/TLS
                    return f"SSL/TLS Data: {raw_payload[:50]}"
                elif packet[TCP].sport == 22 or packet[TCP].dport == 22:  # SSH
                    return f"SSH Data: {raw_payload[:50]}"
                elif packet[TCP].sport == 23 or packet[TCP].dport == 23:  # Telnet
                    return f"Telnet Data: {raw_payload[:50]}"
            return f"TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet:
            return f"UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}"
        elif ICMP in packet:
            return f"ICMP Type: {packet[ICMP].type}"
        else:
            return "Unknown Protocol"

    def save_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            try:
                wrpcap(file_path, self.filtered_packets)
                messagebox.showinfo("Save Packets", f"Packets saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"An error occurred while saving packets: {str(e)}")

    def load_packets(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            try:
                self.packets = rdpcap(file_path)
                self.filtered_packets = self.packets[:]
                self.update_display()
                messagebox.showinfo("Load Packets", f"Packets loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Load Error", f"An error occurred while loading packets: {str(e)}")

    def view_packet_details(self):
        selected_item = self.tree.selection()
        if selected_item:
            packet = self.filtered_packets[int(self.tree.index(selected_item[0]))]
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Packet Details")
            text = tk.Text(detail_window, wrap=tk.WORD)
            text.insert(tk.END, str(packet))
            text.pack(expand=True, fill='both')
        else:
            messagebox.showwarning("View Packet Details", "No packet selected")

    def view_statistics(self):
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "ARP": 0, "FTP": 0, "SMTP": 0, "HTTP": 0, "HTTPS": 0, "SSL/TLS": 0, "SSH": 0, "Telnet": 0, "Other": 0}
        for packet in self.filtered_packets:
            protocol_name = self.get_protocol_name(packet)
            if protocol_name in proto_counts:
                proto_counts[protocol_name] += 1
            else:
                proto_counts["Other"] += 1

        stats_window = tk.Toplevel(self.root)
        stats_window.title("Statistics")
        stats_text = tk.Text(stats_window, wrap=tk.WORD)
        stats_text.insert(tk.END, "\n".join([f"{proto}: {count}" for proto, count in proto_counts.items()]))
        stats_text.pack(expand=True, fill='both')

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
