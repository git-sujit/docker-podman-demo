FROM uba-impala:v2

# get the ARG from command-line [defaults to impala:1010]
ARG IMPALA_USER=impala
ARG IMPALA_UID=1010
ARG IMPALA_GROUP=impala
ARG IMPALA_GID=1010

USER root

WORKDIR /

COPY impala /etc/default
COPY core-site.xml /etc/impala/conf/
COPY hdfs-site.xml /etc/impala/conf/
COPY hive-site.xml /etc/impala/conf/

RUN chmod +x ./*.sh

# write impala logs to host disk on bind mount /var/vcap
# impala uid must match host in order to write logs to host
RUN usermod -u $IMPALA_UID $IMPALA_USER
RUN groupmod -g $IMPALA_GID $IMPALA_GROUP
RUN rm -rf /var/log/impala
RUN ln -sv /var/vcap/sys/log/impala /var/log/impala

# grant impala user and group permission to run impala services
RUN chown $IMPALA_USER:$IMPALA_GROUP /var/run/impala/*

EXPOSE 21000 21050 25000 25010 25020

ENTRYPOINT ["/bin/bash", "-c", "./impala-bootstrap.sh && tail -f /dev/null"]