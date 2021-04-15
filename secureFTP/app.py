from secureFTP.client.client import FTPClient
from secureFTP.server.server import FTPServer

""" Temporary(?) file for testing different client configurations and parallelism, might remove later"""

def app_main():
    # Create client_1 instance
    client_1 = FTPClient(address="B", server_address="A", net_path="./network/")

    client_1.init_session()

    # Create client_2 instance
    client_1 = FTPClient("C", "./network/")




if __name__ == "__main__":
    app_main()
