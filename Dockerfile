FROM erlang:21.0

RUN echo 'deb http://ftp.debian.org/debian stretch-backports main' > \
         /etc/apt/sources.list.d/backports.list \
 && apt-get update \
 && apt-get install -t stretch-backports -y dnsutils ipvsadm libsodium-dev \
 && rm -rf /var/lib/apt/lists/*

CMD ["bash"]
