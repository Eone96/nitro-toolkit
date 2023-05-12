#!/bin/bash

while true
do
    echo "---- $(date +%F%t%T) ----"
    free -h
    echo "--------"
    top -bn 1 | grep Cpu
    sleep 2s
done