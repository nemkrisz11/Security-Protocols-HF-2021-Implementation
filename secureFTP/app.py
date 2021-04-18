from secureFTP.client.client import FTPClient
from secureFTP.server.server import FTPServer
import getopt
import sys


""" Temporary(?) file for testing different client configurations and parallelism, might remove later"""


def app_main(net_path):
    # Create client_1 instance
    client_1 = FTPClient(address="C", server_address="A", net_path=net_path)
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

    for opt, arg in opts:
        if opt == '-h' or opt == '--help':
            print("Usage: python app.py -p <network path>")
            sys.exit(0)
        elif opt == '-p' or opt == '--path':
            net_path = arg

    app_main(net_path)
