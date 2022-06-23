FROM tomcat:8-jdk8-corretto

RUN yum remove -y java-1.8.0-amazon-corretto-devel && \
    yum update -y && \
    yum install -y java-1.7.0-openjdk && \
    yum clean all && \
    rm -rf /usr/lib/jvm/java-1.8.0-amazon-corretto && \
    rm -rf /var/cache/yum

ENV JAVA_HOME=/usr/lib/jvm/jre-1.7.0-openjdk

ENV RUN_USER            tomcat
ENV RUN_GROUP           tomcat

# Add a tomcat user
RUN groupadd -r ${RUN_GROUP} && useradd -g ${RUN_GROUP} -d ${CATALINA_HOME} -s /bin/bash ${RUN_USER} && \
    chown -R tomcat:tomcat $CATALINA_HOME

USER tomcat

EXPOSE 80
