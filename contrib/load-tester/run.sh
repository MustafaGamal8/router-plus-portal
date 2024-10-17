#!/bin/bash

# On Ubuntu, you may want this:
# echo "core.%e.%p" > /proc/sys/kernel/core_pattern
# http://stackoverflow.com/a/18368068

function main() {
    if [[ -z "$SUDO_USER" ]]; then
        echo "Hey, you should run this with sudo"
        exit 1
    fi

    echo "core.%e.%p" > /proc/sys/kernel/core_pattern
    ulimit -c unlimited

    COUNT=40
    echo "Make sure to configure GatewayInterface in router-plus-portal_mock.conf"

    ./generate_interfaces.sh start $COUNT || exit 1

    sudo -u "$SUDO_USER" ./mock_auth.py &
    MA_PID="$!"

    # work around libtool stuff - do not execute wrapper!
    #EXEC="../../src/.libs/router-plus-portal"
    #export LD_LIBRARY_PATH="../../libhttpd/.libs/"
    # trace-children is necessary because of the libtool wrapper -.-
    #valgrind --leak-check=full --trace-children=yes --trace-children-skip=/bin/sh \
    #    --log-file=valgrind.log $EXEC -d 7 -f -c router-plus-portal-mock.conf -a /tmp/arp 2> router-plus-portal.log &

    # for -fsanitize=address
    export ASAN_OPTIONS=check_initialization_order=1
    export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.5


    ../../src/router-plus-portal -d 7 -f -c router-plus-portal-mock.conf -a /tmp/arp &> router-plus-portal.log &
    WD_PID="$!"


    sudo -u "$SUDO_USER" ./plot_memory.sh $WD_PID &
    M_PID="$!"

    IF=`sudo -u "$SUDO_USER" grep GatewayInterface router-plus-portal-mock.conf | cut -f 2 -d ' '`

    echo "Waiting for router-plus-portal to come up"

    sleep 10

    ./fire_wdctl.py \
        --target-interface $IF \
        --source-interface-prefix mac \
        --source-interface-count $COUNT \
        --process-count 3 &
    WDCTL="$!"

    sudo -u "$SUDO_USER" ./fire_requests.py \
        --target-interface $IF \
        --source-interface-prefix mac \
        --source-interface-count $COUNT \
        --process-count 3
    REQUESTS="$!"


}

function cleanup() {

    kill $MA_PID
    kill $WD_PID
    kill $M_PID
    kill $WDCTL
    kill $REQUESTS
    ./generate_interfaces.sh stop $COUNT

}

trap cleanup EXIT

main
