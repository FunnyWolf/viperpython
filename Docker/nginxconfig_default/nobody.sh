#!/bin/sh

Echo_c(){
    echo "\033[1;33m\n$1\n\033[0m"
}

Rand_Name(){
    openssl rand -base64 8 | md5sum | cut -c1-8
}

Gen_Cert(){
    Echo_c "生成/root/.rnd随机文件"
    openssl rand -writerand /root/.rnd
    Echo_c "生成随机名称"
    rndca=$(Rand_Name)
    rndserver=$(Rand_Name)
    rndclient=$(Rand_Name)

    Echo_c "更新Server SSL证书"
    openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out server.crt -keyout server.key -subj /C=SI/ST=$rndca/L=$rndca/O=$rndca/OU=$rndca/CN=$rndca
}



Echo_c "输入Viper端口 [默认60000],回车直接回复到初始配置" && read -r INPUTNGINXPORT

if [ -z "$INPUTNGINXPORT" ]; then
    tee viper.conf <<-'EOF'
listen 60000;
location / {
  root   /root/viper/dist;
}
EOF
    Echo_c "重启Docker中的nginx服务"
    docker exec -it viper-c bash -c "viper restartnginx"
    exit
fi

if [ $INPUTNGINXPORT -gt 0 ]&&[ $INPUTNGINXPORT -lt 65535 ] 2>/dev/null ;then
    Echo_c "使用端口号: $INPUTNGINXPORT"
else
    Echo_c "输入端口号不符合要求,使用默认端口60000"
    INPUTNGINXPORT=60000
fi

Echo_c "输入Nginx认证密码,回车直接清除密码" && read -r INPUTNGINXPASS

Echo_c "Nginx认证用户名: root 密码: $INPUTNGINXPASS"
Echo_c "写入密码到htpasswd"
docker exec -it viper-c bash -c "htpasswd -bc /root/viper/Docker/nginxconfig/htpasswd root $INPUTNGINXPASS"
Gen_Cert


tee viper.conf <<-'EOF'
listen INPUTNGINXPORT;
location / {
  root /root/viper/dist;
  auth_basic "root";
  auth_basic_user_file /root/viper/Docker/nginxconfig/htpasswd;
}
EOF

sed -i "s/INPUTNGINXPORT/$INPUTNGINXPORT/g" viper.conf

Echo_c "重启Docker中的nginx服务"
docker exec -it viper-c bash -c "viper restartnginx"

Echo_c "配置完成"
