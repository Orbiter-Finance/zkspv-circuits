FROM ubuntu:latest
LABEL authors="sutai"

ENTRYPOINT ["top", "-b"]