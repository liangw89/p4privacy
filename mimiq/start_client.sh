# short shell script to start the toy quic client

# modify the line below to change the number of requests client send to server
requests=10

# modify the line below to navigate to wherever you installed the chromium src code
cd /home/osboxes/chromium/src
./out/Debug/quic_client --host=10.0.1.3 --port=6121 --disable_certificate_verification https://www.example.org --num_requests=$requests