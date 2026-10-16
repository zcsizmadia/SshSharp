# Throwaway SSH servers for the CI interop matrix: OpenSSH, Dropbear, AsyncSSH or Apache MINA SSHD on a digest-pinned Alpine image
# (BASE, set by the workflow). Never published or used outside CI.
ARG BASE
FROM ${BASE}
ARG SERVER=openssh
# The entrypoint starts the server the image was built for.
ENV SSH_SERVER=${SERVER}
# The scp program too, for the SCP interop tests. Dropbear runs an external sftp-server for the sftp subsystem, at the path it was
# built with (/usr/libexec/sftp-server); Alpine's OpenSSH package installs one in /usr/lib/ssh. AsyncSSH is a pinned release from
# PyPI, on Alpine's Python and cryptography; su-exec runs it as the test account, and the scp program lets the SCP tests find it
# (AsyncSSH serves scp commands itself). MINA SSHD is a pinned release from Maven Central, each jar checked against its SHA-256,
# run from source by Alpine's JDK (MINA serves scp commands itself too).
RUN if [ "$SERVER" = "dropbear" ]; then \
      apk add --no-cache dropbear dropbear-scp openssh-sftp-server \
      && mkdir -p /usr/libexec && ln -sf /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; \
    elif [ "$SERVER" = "asyncssh" ]; then \
      apk add --no-cache python3 py3-pip py3-cryptography su-exec openssh-client \
      && pip install --no-cache-dir --break-system-packages asyncssh==2.21.0; \
    elif [ "$SERVER" = "mina" ]; then \
      apk add --no-cache openjdk21-jdk su-exec openssh-client \
      && mkdir /mina && cd /mina \
      && M=https://repo1.maven.org/maven2 \
      && wget -q $M/org/apache/sshd/sshd-common/2.20.0/sshd-common-2.20.0.jar $M/org/apache/sshd/sshd-core/2.20.0/sshd-core-2.20.0.jar \
           $M/org/apache/sshd/sshd-sftp/2.20.0/sshd-sftp-2.20.0.jar $M/org/apache/sshd/sshd-scp/2.20.0/sshd-scp-2.20.0.jar \
           $M/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar $M/org/slf4j/slf4j-simple/1.7.36/slf4j-simple-1.7.36.jar \
           $M/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar \
      && printf '%s\n' \
           "55612c7c6a03302940c047d8b8b80761e963f4c529a032f47acda99a1a064334  sshd-common-2.20.0.jar" \
           "0f2fd957d1c7162b7fa682942e30de21be3377b98d698b6b5b729657df74e576  sshd-core-2.20.0.jar" \
           "70ce2e0e35b1106c4371471fb93313e67e0ceab8f127bc09432e115f67a5089e  sshd-sftp-2.20.0.jar" \
           "efb1f2c004ef847ec0bf25d8de223da2d7b162857c5b0e1f3fe1d04aa08d7e29  sshd-scp-2.20.0.jar" \
           "d3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0  slf4j-api-1.7.36.jar" \
           "2f39bed943d624dfa8f4102d0571283a10870b6aa36f197a8a506f147010c10f  slf4j-simple-1.7.36.jar" \
           "4dda1120db856640dbec04140ed23242215a075fe127bdefa0dcfa29fb31267d  eddsa-0.3.0.jar" \
         | sha256sum -c -; \
    else apk add --no-cache openssh-server openssh-client; fi \
 && adduser -D -s /bin/sh sshsharp
COPY entrypoint.sh /entrypoint.sh
COPY asyncssh_server.py /asyncssh_server.py
COPY MinaServer.java /MinaServer.java
RUN chmod +x /entrypoint.sh
EXPOSE 22 2222
ENTRYPOINT ["/entrypoint.sh"]
