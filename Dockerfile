FROM openjdk:11.0.5-jre
ENV PROFILE=
ENV SERVER_PORT=8080

EXPOSE ${SERVER_PORT}

RUN mkdir -p /app/in/
RUN mkdir -p /app/config/
RUN mkdir -p /var/logs/microservice/

VOLUME /app/in/

COPY ./target/central-authentication-1.0-SNAPSHOT.jar /app/app.jar
COPY ./target/classes/application.yml /app/config/application.yml
COPY ./target/classes/logback-spring.xml /app/config/logback-spring.xml


ENTRYPOINT java -Xss1m -Xmx512m -noverify -Djava.security.egd=file:/dev/./urandom -jar \
-Dspring.profiles.active=$PROFILE \
-Dlogging.config=file:///app/config/logback-spring.xml \
-Dspring.config.location=file:///app/config/application.yml \
-Dcom.sun.net.ssl.checkRevocation=false \
/app/app.jar
