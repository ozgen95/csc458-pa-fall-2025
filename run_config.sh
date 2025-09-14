#!/bin/bash

pip install -r requirements.txt

cd pox_module
sudo python3 setup.py develop

pkill -9 sr_solution
pkill -9 sr

