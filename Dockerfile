FROM linuxserver/openssh-server

COPY entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]