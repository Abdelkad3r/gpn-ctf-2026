FROM eclipse-temurin:26 AS challenge
EXPOSE 1337

COPY my-jdk /my-jdk
COPY leftovers.jar cache.aot /app/

WORKDIR /app/

ENTRYPOINT /my-jdk/bin/java -XX:AOTCache=cache.aot -jar leftovers.jar
