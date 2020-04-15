# Docker Guide

This repository has a `Dockerfile` in the root which builds an image with the
`lighthouse` binary installed.

A pre-built image is available on Docker Hub and the
[sigp/lighthouse](https://github.com/sigp/lighthouse-docker) repository
contains a full-featured `docker-compose` environment.

## Obtaining the Docker image

There are two ways to obtain the docker image, either via Docker Hub or
building the image from source. Once you have obtained the docker image via one
of these methods, proceed to [Using the Docker image](#using-the-docker-image).

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

To build the image from source, navigate to
the root of the repository and run:

```bash
$ docker build . -t lighthouse:local
```

The build will likely take several minutes. Once it's built, test it with:

```bash
$ docker run lighthouse:local lighthouse --help
```

## Using the Docker image

You can run a Docker beacon node with the following command:

```bash
$ docker run -p 9000:9000 -p 127.0.0.1:5052:5052 -v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse lighthouse beacon --http --http-address 0.0.0.0
```

> The `-p` and `-v` and values are described below.

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

If you use the `--http` flag you may also want to expose the HTTP port with `-p
127.0.0.1:5052:5052`.

```bash
$ docker run -p 9000:9000 -p 127.0.0.1:5052:5052 sigp/lighthouse lighthouse beacon --http --http-address 0.0.0.0
```
