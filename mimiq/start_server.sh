# short script to start a toy quic server

# modify the line below to navigate to wherever you installed the chromium src code
cd /home/osboxes/chromium/src
./out/Debug/quic_server --quic_response_cache_dir=/home/osboxes/repos/mimiq/website/www.example.org --certificate_file=net/tools/quic/certs/out/leaf_cert.pem --key_file=net/tools/quic/certs/out/leaf_cert.pkcs8 &
