#!/usr/bin/env bash

# update geolite
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb -O /root/viper/STATICFILES/STATIC/GeoLite2-ASN.mmdb
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb -O /root/viper/STATICFILES/STATIC/GeoLite2-City.mmdb
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb -O /root/viper/STATICFILES/STATIC/GeoLite2-Country.mmdb

cd /root/viper/ || exit
mv ./Docker/CONFIG_docker.py CONFIG.py
chmod 755 viper.py
chmod 755 ./STATICFILES/Tools/dns_server
find . -type f -exec dos2unix {} \;>/dev/null 2>1

# clean viper
rm -rf /root/viper/*.lock
rm -rf /root/viper/*.pid
rm -rf /root/viper/*.sock
chmod 777 -R /root/viper/Docker/db/
rm -rf /root/viper/Docker/db/*
rm -rf /root/viper/Docker/log/*
rm -rf /root/viper/Docker/module/*
rm -rf /root/.msf4/logs/*
rm -rf /root/viper/STATICFILES/MODULES_DEBUG/*
rm -rf /root/viper/STATICFILES/SOURCE/*
rm -rf /root/viper/STATICFILES/TMP/*

# format msf file
cd /root/metasploit-framework || exit
find . -name *.py -exec dos2unix {} \;>/dev/null 2>1
find . -name *.py -exec chmod 755 {} \;>/dev/null 2>1

# update gem
export PATH="$HOME/.rbenv/bin:$PATH"
eval "$(rbenv init -)"
cd /root/metasploit-framework || exit
bundle config --delete 'mirror.https://rubygems.org/'
bundle install
gem clean
bundle install
rm -rf ~/.rbenv/versions/3.*/lib/ruby/gems/3.*/cache/
rm -rf ~/.rbenv/versions/3.0.5/share/

# update rex-core /rex-socket
cp -r /root/rex-core/lib /root/.rbenv/versions/3.*/lib/ruby/gems/3.*/gems/rex-core-*/
rm -rf /root/rex-core
cp -r /root/rex-socket/lib /root/.rbenv/versions/3.*/lib/ruby/gems/3.*/gems/rex-socket-*/
rm -rf /root/rex-socket

# clean .git
rm -rf /root/viper/.git
rm -rf /root/metasploit-framework/.git

# clean install cache
rm -rf /root/.cache/*
rm -rf /root/.bundle/cache
rm -rf /root/.gem/specs
rm -rf /usr/local/lib/ruby/gems/3.0.0/doc/*
rm -rf /usr/local/lib/ruby/gems/3.0.0/cache/*
rm -rf /usr/lib/python3
rm -rf /usr/local/lib/python3.9/test

# clean metasploit-framework
rm -rf /root/metasploit-framework/external/*
rm -rf /root/metasploit-framework/documentation/*
rm -rf /root/metasploit-framework/docs/*
rm -rf /root/metasploit-framework/spec/*
rm -rf /root/metasploit-framework/docker/*
rm -rf /root/metasploit-framework/test/*
rm -rf /usr/local/share/*

# mkdir
mkdir -p /root/viper/Docker/module
mkdir -p /root/viper/Docker/log
mkdir -p /root/viper/Docker/db
mkdir -p /root/viper/Docker/nginxconfig
mkdir -p /root/viper/STATICFILES/TMP

# service
cp /root/viper/Docker/puma /etc/init.d/puma
chmod 755 /etc/init.d/puma
dos2unix /etc/init.d/puma

# history
history -c
echo >/root/.bash_history
