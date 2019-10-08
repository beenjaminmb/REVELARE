#!/bin/bash

./dift_bridge_up.sh
./dift_ifup.sh $1
./dift_route_up.sh
