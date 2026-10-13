# Throwaway SSH servers for the CI interop matrix: OpenSSH or Dropbear on a digest-pinned Alpine image (BASE, set by the workflow).
# Never published or used outside CI.
ARG BASE
FROM ${BASE}
ARG SERVER=openssh
RUN if [ "$SERVER" = "dropbear" ]; then apk add --no-cache dropbear; else apk add --no-cache openssh-server; fi \
 && adduser -D -s /bin/sh sshsharp
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
