# Docker Guide

## Docker Hub

Lighthouse maintains the
[sigp/lighthouse](https://hub.docker.com/repository/docker/sigp/lighthouse/)
Docker Hub repository which provides an easy way to run Lighthouse without
building the image yourself.

Download and test the image with:

```bash
$ docker run sigp/lighthouse lighthouse --help
```

> Note: when you're running the Docker Hub image you're relying upon a
> pre-built binary instead of building from source.

## Building the Docker Image

This repository has a `Dockerfile` in the root which builds an image with the
`lighthouse` binary installed.

To use the image, first build it (this will likely take several minutes):

```bash
$ docker build . -t lighthouse:local
```

Once it's built, run it with:

```bash
$ docker run lighthouse:local lighthouse --help
```

## Using volumes

Lighthouse uses the `/root/.lighthouse` directory inside the Docker image to
store the configuration, database and validator keys. Users will generally want
to create a bind-mount volume to ensure this directory persists between `docker
run` commands.

The following example runs a beacon node with the data directory
mapped to the users home directory:

```bash
$ docker run -v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse lighthouse beacon
```
