
#Name: Emanuelle Pelayo
#Date: April 29th, 2024
#CPE 400 - Computer Communication Networks Final Project
#Description:
    #Python program that analyzes a .pcapng file captured from WireShark
    #from a PlayStation Remote Play session and flags any unsecure packets that
    #were transmitted, displaying them to the user. 

from scapy import all
from scapy.all import TCP #import TCP functionality
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet functionality

results = [] # List to hold T/F of results (T = secure packet, F = unsecure packet)
unsecurePackets = [] # List to hold any unsecure packets
packetIndex = 0  #keep track of packet index

load_layer("http") # To detect for HTTP Requests

packets = rdpcap("PS4_Remote_Play_Packets.pcapng", 10000) # Capture packets from the .pcapng file
#Packet fornat: Ether / IP / UDP 66.22.234.14:50008 > 192.168.1.247:58956 / Raw


#Checks to see whether a packet used FTP or not
def isFTP(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw): #FTP relies on TCP
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:#FTP uses port 21, so checking for it
            return True
        else:
            return False
    return False


#Checks to see whether a packet used RDP or not
def isRDP(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw): # RDP uses TCP, checking for TCP
        if packet[TCP].dport == 3389 or packet[TCP].sport == 3389: #RDP uses TCP port 3389
            return True 
        else:
            return False
        
    return False


#Checks to see whether a packet used unencrypted SMTP or not
def isUnencryptedSMTP(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw): #SMTP uses TCP, assuming it uses IP b/c TCP
        #unencrypted SMTP uses port 25, encrypted SMTP uses port 587
        if packet[TCP].dport == 25 or packet[TCP].sport == 25:
            return True
        else:
            return False
    return False

    
#Checks each packet for common unsafe protocols
def isSecure(packet):
    if packet.haslayer(HTTPRequest): 
        unsecurePackets.append(packet) #add the packet to the list of unsecure packets
        return False
    elif isFTP(packet):
        unsecurePackets.append(packet) #add the packet to the list of unsecure packets
        return False
    elif isRDP(packet): #Risky, as it provides complete network access over unsecure RDP ports 
        unsecurePackets.append(packet) #add the packet to the list of unsecure packets
        return False
    elif isUnencryptedSMTP(packet): #transfers data in plain text, unsafe
        #SMTP port 25 is insecure, as it handles unencrypted SMTP submissions. SMTP port 587 is secure, 
        #as it encrypts data.
        unsecurePackets.append(packet) #add the packet to the list of unsecure packets
        return False
    
    return True


#analyze each packet. If it is secure, add True to results. Otherwise, add False.
def analyze_packet(packet, packetIndex):
    if isSecure(packet):
        results.append(True)
        packetIndex = packetIndex + 1
        
    else:
        results.append(False)
        packetIndex = packetIndex + 1


#print the results of the analysis to the terminal
def printResults():
    RED = '\033[91m'
    GREEN = '\033[92m'
    # ANSI escape code to reset text color
    RESET = '\033[0m'
    
    if __builtins__.all(results): #if all packets are secure, print a green message  
        print(GREEN + "All clear. All packets are secure." + RESET)

    else: #An unsecure packet has been detected, print it in red
        print(RED + "Unsecure packets detected..." + RESET)
        for packet in unsecurePackets: #print all unsecure packets in red color
            print(RED + packet.summary() + RESET)


def main ():
    #analyze each packet individually
    for packet in packets:
        analyze_packet(packet, packetIndex)

    #print the results of the analysis to the terminal
    printResults()


main() #call main to execute the program

