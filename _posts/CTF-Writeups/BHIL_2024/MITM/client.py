import struct
import socket
import random
import pickle
import base64
import marshal
import types
import argparse
from sys import exit
from scapy.all import rdpcap, IP, Raw

__author__ = "Noam Afergan"
__ctf__ = "Intent CTF 2024"
__challenge__ = "Mitm"
__category__ = "Forensics"
__date__ = "2024-11-19"

main_data = b""

def get_data():
    """
    This Generator get packets from the pcapng file and 
    add them into generat data var that simulate socket communication 
    by getting the data from this var insted from the socket.
    """
    global main_data
    packets = rdpcap("mitm.pcapng")
    for i, packet in enumerate(packets):
        if IP in packet and hasattr(packet[IP], 'payload') and len(packet[IP].payload) > 0:
            if packet[IP].src == "13.37.13.37" and Raw in packet:
                main_data += bytes(packet[Raw].load)
                yield True
    yield False

#var that store the generator
data_gen = get_data()

def data_addr(size):
    """
    This function add more data into the global main_data var,
    this function simulate the recv() data from socket function.
    """
    global main_data
    while len(main_data) < size:
        if not next(data_gen):
            print("[*] Error: End of data")
            exit(0)

def process_pcap():
    """
    This function get the data from the global data var by using this communication protocol:
    [4      bytes] - size
    [{size} bytes] - msg
    """
    global main_data
    data_addr(4)
    raw_msglen = main_data[0:4]
    if not raw_msglen:
        return 0              
    msglen = struct.unpack('>I', raw_msglen)[0]
    data_addr(4 + msglen)
    res = main_data[4:4 + msglen]
    main_data = main_data[4 + msglen:]
    return res
                
def send_msg(sock, msg):
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recv_msg():
    """
    update the recv_msg func to return the messages that it recv 
    from the global main_data that recv them from the pcapng file insted from the real socket.
    """
    try:
        return process_pcap()
    except StopIteration:
        print("No more packets in PCAP file.")
        return None



def enc_msg(key, msg: bytes):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = int(key)

    char_based_key = key % 256

    ret = []
    for char in msg:
        ret.append(char ^ char_based_key)
        char_based_key = (char_based_key + 13) % 256
    return bytes(ret)


def dec_msg(key, msg):
    return enc_msg(key, msg)


def whitefield_command(variables, variable, value):
    variables[variable] = value


def amir_command(variables, variable, value):
    if not variable in variables:
        variables[variable] = []
    variables[variable].append(value)


def exit_command(variables, variable, value):
    flag = ''
    enc_key = pickle.loads(base64.b64decode(value))
    enc_secret = variables[variable]

    # decrypt secret
    for i in range(len(enc_secret)):
        flag += chr(enc_secret[i] ^ enc_key[i])
    print(flag)
    exit(0)
    variables['flag'] = flag


class CommandHandler:
    def __init__(self) -> None:
        self.variables = {}
        self.commands = {}
        self.commands['whitefield'] = whitefield_command
        self.commands['amir'] = amir_command
        self.commands['exit'] = exit_command
        self.commands['add_new_command'] = self.add_new_command

    def add_new_command(self, command, func):
        func = marshal.loads(base64.b64decode(func))
        self.commands[command] = types.FunctionType(func, globals(), command)

    def handle_command(self, command):
        if type(command) == bytes:
            command = command.decode('utf-8')
        command = command.split(' ')
        if len(command) == 0:
            return
        if command[0] == 'add_new_command':
            self.add_new_command(command[1], command[2])
            return
        if command[0] in self.commands:
            func_to_call = self.commands[command[0]]
            if command[0] != 'add_new_command' and command[0] != 'exit':
                command[2] = int(command[2])
            func_to_call(self.variables, command[1], command[2])
        else:
            print("Unknown command: ", command[0])


def main():
    try:
        # Diffie Helman Key Swap
        modulus = int(recv_msg().decode())
        base = int(recv_msg().decode())
        print(f"Received modulus: {modulus}, base: {base}")
        client_secret = (base + 2) * 15
        step_A = int(recv_msg().decode())
        step_B = pow(base, client_secret, modulus)        
        key = pow(step_A, client_secret, modulus)
    except Exception as e:
        print("Error in key swap, exiting...")
        print(e)
        exit()

    handler = CommandHandler()
    handler.variables['key'] = key

    while True:
        msg = recv_msg()
        if not msg:
            break

        if msg == b"Invalid response":
            print("Invalid response, exiting...")
            break
        msg = dec_msg(key, msg)

        if msg == 'exit':
            break

        if type(msg) == bytes:
            msg = msg.decode()

        handler.handle_command(msg)
        key = handler.variables['key']

    print("Closing connection... Bye!")


if __name__ == '__main__':
    main()
