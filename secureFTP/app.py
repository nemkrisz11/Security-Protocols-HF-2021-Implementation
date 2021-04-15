from secureFTP.client.client import FTPClient
from secureFTP.server.server import FTPServer


def main():
    # Create server instance
    server = FTPServer("A", "./network/")

    # Create client_1 instance
    client_1 = FTPClient("B", "./network/")

    # Create client_2 instance
    client_1 = FTPClient("C", "./network/")




if __name__ == "__main__":
    main()
