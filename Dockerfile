FROM bash:4.4
MAINTAINER Joachim Jabs <joachim.jabs@brainwave-software.de>

RUN apk add --no-cache file netcat-openbsd socat jq

WORKDIR /opt/bashapi

# Install the API shell script
ADD bashapi.sh /opt/bashapi/bashapi.sh
ADD bashapi.conf /opt/bashapi/conf/bashapi.conf
ADD api /opt/bashapi/api


# Make it executable
RUN chmod 755 /opt/bashapi/bashapi.sh
ENV TCP_PORT 9900

CMD socat TCP-LISTEN:${TCP_PORT},reuseaddr,fork system:/opt/bashapi/bashapi.sh