from secureFTP.client.client import FTPClient
from secureFTP.server.server import FTPServer
import getopt
import sys


""" Temporary(?) file for testing different client configurations and parallelism, might remove later"""


def app_main(net_path, users_folder):
    # Create client_1 instance
    client = FTPClient(address="C", server_address="A", net_path=net_path, users_dir=users_folder)
    client.init_session()



if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:', longopts=['help', 'path='])
    except getopt.GetoptError:
        print("Usage: python app.py -p <network path>")
        sys.exit(1)

    net_path = "./secureFTP/network/"
    users_folder = "./secureFTP/client/users/"

    for opt, arg in opts:
        if opt == '-h' or opt == '--help':
            print("Usage: python app.py -p <network path>")
            sys.exit(0)
        elif opt == '-p' or opt == '--path':
            net_path = arg

    app_main(net_path, users_folder)
