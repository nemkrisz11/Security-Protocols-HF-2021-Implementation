export PYTHONPATH="$PYTHONPATH:$PWD/secureFTP/"

python3 ./secureFTP/netsim/network.py -p "./secureFTP/network/" -a "ABC" --clean &
echo "testpassword" | python3 ./secureFTP/server/server.py -p "./secureFTP/network/" -a "A" -u "./server/users/" &
python3 ./secureFTP/client/client.py -p "./secureFTP/network/" -a "B" -s "A" -u "./client/users/"

pkill -f server.py
pkill -f network.py
