import socket


def tcp_client(target_host:str = "localhost", target_port:int = 9998):
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host,target_port))
    client.send(b"GET / HTTP/1.1\r\nHost: test-host\r\n\r\n")

    response = client.recv(4096)
    client.close()

    return response.decode()

if __name__ == "__main__":
    print(tcp_client())
