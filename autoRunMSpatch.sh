#! /bin/bash
export https_proxy=http://webproxy.f.corp.services:80
export http_proxy=http://webproxy.f.corp.services:80
source /data/scripts/asr/bin/activate
myvar="$PWD"
cd /data/scripts/msPatch/
python3 ./msPatch.py
deactivate
cd "$myvar"