from scapy.all import *

allow_list = ['192.168.1.1']

def packet_allowed(packet):
	if IP in packet:
		return packet[IP].src in allow_list
	return false

def packet_callback(packet):
	if packet_allowed(packet):
		print(f"PACKET ALLOWED: {packet.summary()}")
	else:
		print(f"PACKET BLOCKED: {packet.summary()}")

sniff(prn=packet_callback, filter="ip", store=0)

