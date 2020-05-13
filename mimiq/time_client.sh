#!/bin/bash

# short shell script to time the toy quic client for evaluation

array=(1280 20 40 80 160 320 640 1280)

for requests in "${array[@]}"
do
    echo ""
    echo "Running the client with requests = $requests"
    echo ""

    # modify the line below to navigate to wherever you installed the chromium src code
    cd /home/osboxes/chromium/src
    time ./out/Debug/quic_client --host=10.0.1.3 --port=6121 --disable_certificate_verification https://www.example.org --num_requests=$requests > scratch_output_294712

done
