# Docker Guide

This repository has a `Dockerfile` in the root which builds an image with the
`lighthouse` binary installed.

A pre-built image is available on Docker Hub and the
[sigp/lighthouse](https://github.com/sigp/lighthouse-docker) repository
contains a full-featured `docker-compose` environment.

## Obtaining the Docker image

### Docker Hub

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

### Building the Docker Image

To use the image, first build the `Dockerfile` in the repository root (this
will likely take several minutes):

```bash
$ docker build . -t lighthouse:local
```

Once it's built, test it with:

```bash
$ docker run lighthouse:local lighthouse --help
```

## Using the Docker image

### Volumes

Lighthouse uses the `/root/.lighthouse` directory inside the Docker image to
store the configuration, database and validator keys. Users will generally want
to create a bind-mount volume to ensure this directory persists between `docker
run` commands.

The following example runs a beacon node with the data directory
mapped to the users home directory:

```bash
$ docker run -v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse lighthouse beacon
```

### Ports

In order to be a good peer and serve other peers you should expose port `9000`.
Use the `-p` flag to do this:

```bash
$ docker run -p 9000:9000 sigp/lighthouse lighthouse beacon
```

If you use the `-http` flag you may also want to expose the HTTP port with `-p
5052:5052`.
