#!/bin/bash

for i in {1..254}
do
  seq 1 254 | xargs -P 100 -I{} ./ncat2.sh $1.$i.{} >> ncscan.log
done
