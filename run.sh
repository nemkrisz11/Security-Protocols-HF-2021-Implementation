export PYTHONPATH="$PYTHONPATH:$PWD/secureFTP/"

python3 ./secureFTP/netsim/network.py -p "./secureFTP/network/" -a "ABC" --clean &
python3 ./secureFTP/server/server.py -p "./secureFTP/network/" -a "A" &
python3 ./secureFTP/app.py -p "./secureFTP/network/"
kill %2
kill %1
