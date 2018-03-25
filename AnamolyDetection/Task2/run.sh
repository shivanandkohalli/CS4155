#!/bin/bash
echo "Downloading required libraries"
sudo apt-get install libpcap-dev
pip install scapy-ssl_tls
rm raw_tls.txt
python tls_generator.py $1 > raw_tls.txt
python markov_builder.py > markov_build.txt
dot -Tps markovgraph.dot -o outfile.ps
xdg-open outfile.ps
