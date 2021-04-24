from secureFTP.server.server import FTPServer
import getopt
import sys

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:u:', longopts=['help', 'path=', 'addr=', 'users='])
    except getopt.GetoptError:
        print("Usage: python server.py -p <network path> -a <address>")
        sys.exit(1)

    net_path = "./secureFTP/network/"
    address = "A"
    users_dir = "./secureFTP/server/users/"

    for opt, arg in opts:
        if opt == '-h' or opt == '--help':
            print("Usage: python server.py -p <network path> -a <address> -u <users>")
            sys.exit(0)
        elif opt == '-p' or opt == '--path':
            net_path = arg
        elif opt == '-a' or opt == '--addr':
            address = arg
        elif opt == '-u' or opt == '--users':
            users_dir = arg

    server = FTPServer(address, net_path, users_dir)