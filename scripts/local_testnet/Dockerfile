FROM sigp/lcli:latest-unstable

COPY --from=sigp/lighthouse /usr/local/bin/lighthouse /usr/local/bin/lighthouse

RUN apt-get update && apt-get install -y --no-install-recommends \
  nodejs npm \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN npm -g install ganache-cli

RUN mkdir /app

WORKDIR /app

ADD ./* /app/

