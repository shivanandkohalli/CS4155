#!/bin/sh
echo "Downloading required libraries"
sudo apt-get install libpcap-dev
echo "Compiling"
gcc ./main.c ./events.c ./file_operations.c ./packet_analyser.c -o DAI -lpcap
echo "Running Application"
sudo ./DAI $1 $2 $3 >> "log.txt"
echo "..................................................."
echo "Done parsing!! Open the output CSV file "