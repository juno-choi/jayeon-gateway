FROM openjdk:11-ea-27-jdk-slim

VOLUME /tmp

# jar파일 복사
COPY build/libs/gateway-1.0.jar gateway.jar
ENTRYPOINT ["java","-jar","gateway.jar"]