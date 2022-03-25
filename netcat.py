import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()


class NetCat:
    '''
        Simple Netcat class - 
            Used to run specified commands/operations based on the arguments passed in during terminal based invocation. 

            Attached are Examples:
            Examples:
                netcat.py -t 192.168.1.1 -p 5555 -l -c                      # Command Shell 
                netcat.py -t 192.168.1.1 -p 5555 -l -u=file.txt             # Upload to file 
                netcat.py -t 192.168.1.1 -p 5555 -l -e=\ "cat /etc/passwd\" # Execute command 
                echo 'ABCD' | ./netcat.py -t 192.168.1.1 -p 135             # Echo text to the specified server on port 135 
                netcat.py -t 192.168.1.108 -p 5555                          # Connect to Remote Server 
    '''

    def __init__(self, args, buffer=None):
        '''
            Init for Netcat Class
                - Determines actions based on args, and buffer
                - Could be refactored to:
                    - Utilize Specific Arguments
                    - Dictate UDP/TCP or IPV4/IPV6
        '''

        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        '''
            Run Method
                - Used to determine sending/listening based on user arguments
        '''
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        '''
            Send Method
                Connects to target on specified port and sends data based on buffer. 
                Monitors Recieved Data and breaks loop if less data be recieved. 

                Prints any incoming response, and allows for users to specify new buffer interactively. 
        '''
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()

                    if recv_len < 4096:
                        break

                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())

        except KeyboardInterrupt:
            print('User Terminated. Exiting. ')
            self.socket.close()
            sys.exit()

    def listen(self):
        '''
            Listen:
                Envoked during run - when:
                    - send() is called, to listen for a response. 
                    - listen() is passed in
        '''
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(
                target=self.handle, args=(client_socket,)
            )
            client_thread.start()

    def handle(self, client_socket):
        '''
            Used to define next steps based on passed in params. 
            it either 
                - Executes a command 
                - Uploads a file
                - Starts a remote shell
        '''

        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break

            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)

            message = f'Saved File: {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'BHP:#> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)

                    response = execute(cmd_buffer.decode())

                    if response:
                        client_socket.send(response.encode())

                    cmd_buffer = b''
                except Exception as e:
                    print(f'Exception occured: {e}')
                    self.socket.close()
                    sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(''' Example:
            netcat.py -t 192.168.1.1 -p 5555 -l -c                      # Command Shell 
            netcat.py -t 192.168.1.1 -p 5555 -l -u=file.txt             # Upload to file 
            netcat.py -t 192.168.1.1 -p 5555 -l -e=\ "cat /etc/passwd\" # Execute command 
            echo 'ABCD' | ./netcat.py -t 192.168.1.1 -p 135             # Echo text to the specified server on port 135 
            netcat.py -t 192.168.1.108 -p 5555                          # Connect to Remote Server 
        '''))

    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='Execute Specified Command')
    parser.add_argument('-l', '--listen', action='store_true', help='Listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='Specifies Target Port')
    parser.add_argument('-t', '--target', default='192.168.1.1', help='Specifies Target IP')
    parser.add_argument('-u', '--upload', help='Upload file to specified target')
    args = parser.parse_args()

    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.readline()

    nc = NetCat(args, buffer.encode())
    nc.run()
