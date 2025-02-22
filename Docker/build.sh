#!/usr/bin/env bash

# Define the file paths
ASN_DB="/root/viper/STATICFILES/STATIC/GeoLite2-ASN.mmdb"
CITY_DB="/root/viper/STATICFILES/STATIC/GeoLite2-City.mmdb"
COUNTRY_DB="/root/viper/STATICFILES/STATIC/GeoLite2-Country.mmdb"

# URLs from where to fetch the databases
ASN_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
CITY_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
COUNTRY_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

# Function to update the database file if it is older than 30 days
update_db() {
  local db_path="$1"
  local url="$2"

  # Check if the file exists and is older than 30 days
  if [ ! -f "$db_path" ] || [ $(find "$db_path" -mtime +30 -print) ]; then
    echo "Updating $db_path..."
    wget -q "$url" -O "$db_path"
  else
    echo "No update required for $db_path, not older than 30 days."
  fi
}

# Update each database file if needed
update_db "$ASN_DB" "$ASN_URL"
update_db "$CITY_DB" "$CITY_URL"
update_db "$COUNTRY_DB" "$COUNTRY_URL"

# update pip
pip3 install -r /root/viper/Docker/requirements.txt

# build viperpython
cd /root/viper/ || exit
cp ./Docker/CONFIG_docker.py CONFIG.py
cp ./Docker/CONFIG_docker.py ./Worker/CONFIG.py
chmod 755 viper.py
ln -s /root/viper/viper.py /usr/bin/viper
chmod 755 ./STATICFILES/Tools/dns_server
chmod 755 ./STATICFILES/BIN/nuclei
chmod a+x /root/viper/Docker/start_thin.sh
find . -type f -exec dos2unix {} \; >/dev/null 2>1

# clean viperpython
rm -rf /root/viper/*.lock
rm -rf /root/viper/*.pid
rm -rf /root/viper/*.sock
rm -rf /root/viper/Docker/db/*
rm -rf /root/viper/Docker/log/*
rm -rf /root/viper/Docker/module/*
rm -rf /root/viper/STATICFILES/TMP/*

# mkdir viperpython
mkdir -p /root/viper/Docker/module
mkdir -p /root/viper/Docker/log
mkdir -p /root/viper/Docker/db
mkdir -p /root/viper/Docker/nginxconfig
mkdir -p /root/viper/STATICFILES/TMP
chmod 777 -R /root/viper/Docker/db/
chown elasticsearch:elasticsearch -R /root/viper/Docker/db

# nuclei
/root/viper/STATICFILES/BIN/nuclei -up
/root/viper/STATICFILES/BIN/nuclei -ut -ud /root/viper/STATICFILES/BIN/nuclei-templates

# service
cp /root/viper/Docker/puma /etc/init.d/puma
chmod 755 /etc/init.d/puma
dos2unix /etc/init.d/puma


# format msf file
cd /root/metasploit-framework || exit
find . -name *.py -exec dos2unix {} \; >/dev/null 2>1
find . -name *.py -exec chmod 755 {} \; >/dev/null 2>1

# update gem
export PATH="$HOME/.rbenv/bin:$PATH"
eval "$(rbenv init -)"
cd /root/metasploit-framework || exit
#bundle config --delete 'mirror.https://rubygems.org/'
bundle install
gem clean
bundle install
#cp -r /root/metasploit-framework/data/loot_default /root/.msf4/loot

# clean metasploit-framework
rm -rf /root/metasploit-framework/external/*
rm -rf /root/metasploit-framework/documentation/*
rm -rf /root/metasploit-framework/docs/*
rm -rf /root/metasploit-framework/spec/*
rm -rf /root/metasploit-framework/docker/*
rm -rf /root/metasploit-framework/test/*
rm -rf /usr/local/share/*
rm -rf /root/.msf4/logs/*

# update rex-core /rex-socket
cp -r /root/rex-core/lib /root/.rbenv/versions/3.*/lib/ruby/gems/3.*/gems/rex-core-*/
rm -rf /root/rex-core
cp -r /root/rex-socket/lib /root/.rbenv/versions/3.*/lib/ruby/gems/3.*/gems/rex-socket-*/
rm -rf /root/rex-socket

# clean .git
rm -rf /root/viper/.git
rm -rf /root/metasploit-framework/.git
rm -rf /root/worker/.git

# clean install cache
rm -rf /root/.cache/*
rm -rf /root/.bundle/cache
rm -rf /root/.gem/specs
rm -rf /usr/local/lib/ruby/gems/3.*/doc/*
rm -rf /usr/local/lib/ruby/gems/3.*/cache/*
# rm -rf /usr/lib/python3
# rm -rf /usr/local/lib/python3.9/test
rm -rf ~/.rbenv/versions/3.*/lib/ruby/gems/3.*/cache/
rm -rf ~/.rbenv/versions/3.*/share/
rm -rf ~/.rbenv/versions/3.*/lib/ruby/gems/3.*/doc/

# supervisor
rm -rf /etc/supervisor/conf.d/*
cp /root/viper/Docker/worker.conf /etc/supervisor/conf.d/worker.conf

# elasticsearch
cp /root/viper/Docker/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml
cp /root/viper/Docker/elasticsearch/jvm.options /etc/elasticsearch/jvm.options

# openssl
cp /root/viper/Docker/openssl.cnf /etc/ssl/openssl.cnf

# tmp install
#apt-get install uwsgi-plugin-python3
#rbenv global 3.0.5
# apt-get install nmap -y
# apt install -y apache2-utils

# history
history -c
echo >/root/.bash_history
