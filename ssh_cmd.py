from pydoc import cli
from sys import stderr
import paramiko


def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)

    _, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()

    if output:
        print('---Output---')
        for line in output:
            print(line.strip())


if __name__ == '__main__':
    import getpass
    # I dont know why this is here: but adding the below line as it is in the book...
    # Appears to grab the username from the current env - but why when youre connecting to a remote host...
    # user = getpass.getuser()

    user = input('Username: ')

    # Usered to prompt for password without visual representation
    password = getpass.getpass()

    ip = input('Enter Server IP: ') or 'localhost'
    port = input('Enter Serve Port or <CR>: ') or 2222
    cmd = input('Enter Command or <CR>: ') or 'id'

    ssh_command(ip, port, user, password, cmd)
