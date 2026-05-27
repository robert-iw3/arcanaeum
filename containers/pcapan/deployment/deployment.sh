#!/bin/bash
cd rust-app && docker build -t pcapan:latest .
cd ../web-app && docker build -t pcapan-web:latest .
docker run -d -p 3000:3000 -v $(pwd)/../pcaps:/pcaps -e JWT_SECRET=secret pcapan-web:latest
docker run --rm -v $(pwd)/../pcaps:/pcaps -v $(pwd)/../whitelist.yaml:/whitelist.yaml pcapan:latest --dir /pcaps --whitelist /whitelist.yaml --output /results.json