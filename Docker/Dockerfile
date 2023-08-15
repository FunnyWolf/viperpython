FROM registry.cn-hongkong.aliyuncs.com/toys/viper-base:latest

ARG ZSTD_COMPRESS=true
ARG ZSTD_COMPRESS_LEVEL=22
ARG COMPRESS_LAYER=true

COPY viperpython /root/viper/
COPY vipermsf /root/metasploit-framework/
COPY viperjs/dist /root/viper/dist/
COPY rex-core /root/rex-core/
COPY rex-socket /root/rex-socket/

RUN chmod a+x /root/viper/Docker/build.sh && ./root/viper/Docker/build.sh

ENTRYPOINT ["viper", "init","-pw"]

CMD ["diypassword"]

HEALTHCHECK CMD viper healthcheck
