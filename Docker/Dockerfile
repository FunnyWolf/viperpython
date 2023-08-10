FROM registry.cn-shenzhen.aliyuncs.com/toys/viper-base:latest

COPY viperpython /root/viper/
COPY vipermsf /root/metasploit-framework/
COPY dist /root/viper/dist/
COPY rex-core /root/rex-core/
COPY rex-socket /root/rex-socket/

RUN ["./root/viper/Docker/build.sh"]

ENTRYPOINT ["viper", "init","-pw"]

CMD ["diypassword"]

HEALTHCHECK CMD viper healthcheck