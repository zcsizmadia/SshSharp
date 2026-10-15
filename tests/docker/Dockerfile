# Throwaway SSH servers for the CI interop matrix: OpenSSH or Dropbear on a digest-pinned Alpine image (BASE, set by the workflow).
# Never published or used outside CI.
ARG BASE
FROM ${BASE}
ARG SERVER=openssh
# The scp program too, for the SCP interop tests. Dropbear runs an external sftp-server for the sftp subsystem, at the path it was
# built with (/usr/libexec/sftp-server); Alpine's OpenSSH package installs one in /usr/lib/ssh.
RUN if [ "$SERVER" = "dropbear" ]; then \
      apk add --no-cache dropbear dropbear-scp openssh-sftp-server \
      && mkdir -p /usr/libexec && ln -sf /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; \
    else apk add --no-cache openssh-server openssh-client; fi \
 && adduser -D -s /bin/sh sshsharp
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
