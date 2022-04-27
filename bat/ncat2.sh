#!/bin/bash

ports=(21 22 25 53 80 88 135 139 389 443 445 3389)

for port in ${ports[@]}; do
  #echo $port
  res=$(nc -zw 1 $1 $port; echo $?)
  if [ 0 -eq $res ]; then
    echo $1:$port
  fi
done
