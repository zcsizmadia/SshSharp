# Throwaway SSH servers for the CI interop matrix: OpenSSH or Dropbear on a digest-pinned Alpine image (BASE, set by the workflow).
# Never published or used outside CI.
ARG BASE
FROM ${BASE}
ARG SERVER=openssh
# The scp program too, for the SCP interop tests.
RUN if [ "$SERVER" = "dropbear" ]; then apk add --no-cache dropbear dropbear-scp; else apk add --no-cache openssh-server openssh-client; fi \
 && adduser -D -s /bin/sh sshsharp
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
