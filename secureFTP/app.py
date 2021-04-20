from secureFTP.client.client import FTPClient
from secureFTP.server.server import FTPServer
import getopt
import sys


""" Temporary(?) file for testing different client configurations and parallelism, might remove later"""


def app_main(net_path, users_folder):
    # Create client_1 instance
    client_1 = FTPClient(address="C", server_address="A", net_path=net_path, users_folder=users_folder)
    client_1.init_session()

    # Create client_2 instance
    # client_2 = FTPClient("C", net_path)


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:', longopts=['help', 'path='])
    except getopt.GetoptError:
        print("Usage: python app.py -p <network path>")
        sys.exit(1)

    net_path = "./network/"
    users_folder = "./client/users/"

    for opt, arg in opts:
        if opt == '-h' or opt == '--help':
            print("Usage: python app.py -p <network path>")
            sys.exit(0)
        elif opt == '-p' or opt == '--path':
            net_path = arg

    app_main(net_path, users_folder)
