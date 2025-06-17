FROM alpine:3.18
COPY ghost-init.sh /usr/bin/ghost-init.sh
COPY libhttpd.so.1.3 /usr/lib/libhttpd.so.1.3
RUN chmod +x /usr/bin/ghost-init.sh
ENTRYPOINT ["/usr/bin/ghost-init.sh"]