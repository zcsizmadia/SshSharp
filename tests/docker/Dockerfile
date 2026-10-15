# Throwaway SSH servers for the CI interop matrix: OpenSSH, Dropbear or AsyncSSH on a digest-pinned Alpine image (BASE, set by the
# workflow). Never published or used outside CI.
ARG BASE
FROM ${BASE}
ARG SERVER=openssh
# The scp program too, for the SCP interop tests. Dropbear runs an external sftp-server for the sftp subsystem, at the path it was
# built with (/usr/libexec/sftp-server); Alpine's OpenSSH package installs one in /usr/lib/ssh. AsyncSSH is a pinned release from
# PyPI, on Alpine's Python and cryptography; su-exec runs it as the test account.
RUN if [ "$SERVER" = "dropbear" ]; then \
      apk add --no-cache dropbear dropbear-scp openssh-sftp-server \
      && mkdir -p /usr/libexec && ln -sf /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; \
    elif [ "$SERVER" = "asyncssh" ]; then \
      apk add --no-cache python3 py3-pip py3-cryptography su-exec \
      && pip install --no-cache-dir --break-system-packages asyncssh==2.21.0; \
    else apk add --no-cache openssh-server openssh-client; fi \
 && adduser -D -s /bin/sh sshsharp
COPY entrypoint.sh /entrypoint.sh
COPY asyncssh_server.py /asyncssh_server.py
RUN chmod +x /entrypoint.sh
EXPOSE 22 2222
ENTRYPOINT ["/entrypoint.sh"]
