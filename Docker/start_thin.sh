#!/usr/bin/env bash
export PATH="$HOME/.rbenv/bin:$PATH"
eval "$(rbenv init -)"
cd /root/metasploit-framework || exit
thin -c /root/metasploit-framework -l /root/viper/Docker/log/thin.log --rackup /root/metasploit-framework/msf-json-rpc.ru --address 127.0.0.1 --port 60005 --environment production --daemonize --threaded start