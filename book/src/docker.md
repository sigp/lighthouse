# Docker Guide

Lighthouse maintains the
[sigp/lighthouse](https://hub.docker.com/repository/docker/sigp/lighthouse/)
Docker Hub file which provides an easy way to run Lighthouse without building
the binary yourself. This page contains two separate guides:

- Running Lighthouse using `docker-compose` (easiest).
- Running Lighthouse using the docker image directly (more advanced).


> Note: when you're running the Docker Hub image you're relying upon a
> pre-built binary instead of building from source. If you want the highest
> assurance you're running the _real_ Lighthouse,
> [build the docker image yourself](#building-the-docker-image) instead.


## Running Lighthouse using `docker-compose`

[`docker-compose`](https://docs.docker.com/compose/) is a tool for defining and
running multi-container Docker applications. The
[sigp/lighthouse-docker](https://github.com/sigp/lighthouse-docker) repository
contains a `docker-compose` setup that is likely the easiest way to get started
with the Lighthouse testnet.

Docker does not natively come with `docker-compose`, you must install it
yourself. It is included in most package managers, otherwise it's quite easy to
[install manually](https://docs.docker.com/compose/install/).

### Joining the Lighthouse testnet

Once you have `docker-compose` installed, clone the
[sigp/lighthouse-docker](https://github.com/sigp/lighthouse-docker) repository.

```bash
$ git clone https://github.com/sigp/lighthouse-docker
$ cd lighthouse-docker
```

Then, create a `.env` file with the following contents (these values are
documented
[here](https://github.com/sigp/lighthouse-docker/blob/master/default.env)):

```bash
DEBUG_LEVEL=info
START_VALIDATOR=true
VALIDATOR_COUNT=1
VOTING_ETH1_NODE=http://127.0.0.1:8545
DEPOSIT_VALUE=3200000000
```

Start the `docker-compose` environment (you may need to use `sudo`):

```bash
$ docker-compose up
```


## Building the Docker image

This repository has a `Dockerfile` in the root which builds an image with the
`lighthouse` binary installed.

To use the image, first build it (this will likely take several minutes):

```bash
$ docker build . -t lighthouse
```

Once it's built, run it with:

```bash
$ docker run lighthouse lighthouse --help
```

_Note: the first `lighthouse` is the name of the tag we created earlier. The
second `lighthouse` refers to the binary installed in the image._
