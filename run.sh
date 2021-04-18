export PYTHONPATH="$PYTHONPATH:$PWD/secureFTP/"

cd ./secureFTP

python3 ./secureFTP/netsim/network.py -p "./network/" -a "ABC" --clean &
python3 ./secureFTP/server/server.py -p "./network/" -a "A" -u "./server/users/" &
python3 ./secureFTP/app.py -p "./network/"

kill %2
kill %1
