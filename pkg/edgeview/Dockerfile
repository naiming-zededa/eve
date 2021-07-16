FROM naimingshen/edge-view

COPY edge-view-init.sh /edge-view-init.sh
COPY sshd_config /sshd_config
COPY client-certs/client.crt /client.pem
COPY client-certs/client.key /client.key

RUN apk add openssh-server
RUN ssh-keygen -q -t rsa -N '' -f /id_rsa
RUN cp /id_rsa /etc/ssh/ssh_hostkey

RUN mkdir /root/.ssh
RUN chmod 700 /root/.ssh
RUN cat /id_rsa.pub > /root/.ssh/authorized_keys
RUN chmod 700 /root/.ssh/authorized_keys
RUN cp /id_rsa* /root/.ssh/.
RUN cp /sshd_config /etc/ssh/.

ENTRYPOINT []
CMD ["/edge-view-init.sh"]
