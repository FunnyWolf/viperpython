#!/usr/bin/env bash
cd /root/viper/
mv ./Docker/CONFIG_docker.py CONFIG.py
chmod 755 viper.py
chmod 755 ./Tools/dns_server
find . -type f -exec dos2unix {} \;

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
cd /root/metasploit-framework
find . -name *.py -exec dos2unix {} \;
find . -name *.py -exec chmod 755 {} \;
cp /root/metasploit-framework/data/meterpreter/meterpreter.py /root/.rbenv/versions/3.*/lib/ruby/gems/3.*/gems/metasploit-payloads-*/data/meterpreter/

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
echo > /root/.bash_history