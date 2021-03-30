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

    Echo_c "生成CA证书"
    openssl genrsa -out ca.key 4096
    openssl req -new  -x509 -days 3650 -key ca.key -out ca.crt -subj /C=CN/ST=$rndca/L=$rndca/O=$rndca/OU=$rndca/CN=$rndca

    Echo_c "生成Server证书"
    openssl genrsa -out server.key 4096
    openssl req -new -key server.key -out server.csr -subj /C=CN/ST=$rndserver/L=$rndserver/O=$rndserver/OU=$rndserver/CN=$rndserver

    Echo_c "使用CA证书签发Server证书"
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650

    Echo_c "生成Client证书"
    openssl genrsa -out client.key 4096
    openssl req -new -key client.key -out client.csr -subj /C=CN/ST=$rndclient/L=$rndclient/O=$rndclient/OU=$rndclient/CN=$rndclient

    Echo_c "使用CA证书签发Client证书"
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650

    Echo_c "导出pfx证书,请牢记密码"
    openssl pkcs12 -export -inkey client.key -in client.crt -out client.pfx
}







Echo_c "输入Viper端口 [默认60000]" && read -r INPUTNGINXPORT

Echo_c "是否配置Nginx双向认证? [y/N,默认No]" && read -r input
case $input in
    [yY][eE][sS]|[Yy])
        Gen_Cert
        Echo_c "写入配置到viper.conf"

tee viper.conf <<-'EOF'
listen INPUTNGINXPORT;
ssl_client_certificate /root/viper/Docker/nginxconfig/ca.crt;
ssl_verify_client on;
EOF

        sed -i "s/INPUTNGINXPORT/$INPUTNGINXPORT/g" viper.conf
        Echo_c "请将client.pfx拷贝到本地双击安装,然后重启浏览器!!!"
        ;;
    *)
        Echo_c "写入配置到viper.conf"

tee viper.conf <<-'EOF'
listen INPUTNGINXPORT;
EOF

        sed -i "s/INPUTNGINXPORT/$INPUTNGINXPORT/g" viper.conf
        ;;
esac

Echo_c "重启Docker中的nginx服务"
docker exec -it viper-c bash -c "viper restartnginx"

Echo_c "配置完成"
