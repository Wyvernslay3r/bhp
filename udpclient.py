import socket


def udp_client(target_host:str="127.0.0.1",target_port:int=9997):
    
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b"some_data", (target_host, target_port))
    
    data, addr = client.recvfrom(4096)
    client.close()
    return(data.decode(), addr)
    
if __name__ == "__main__":

    print(udp_client())