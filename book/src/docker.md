# Docker Guide

There are two ways to obtain a Lighthouse Docker image:

1. [Docker Hub](#docker-hub), or
2. By [building a Docker image from source](#building-the-docker-image).

Once you have obtained the docker image via one of these methods, proceed to [Using the Docker
image](#using-the-docker-image).

## Docker Hub

Lighthouse maintains the [sigp/lighthouse][docker_hub] Docker Hub repository which provides an easy
way to run Lighthouse without building the image yourself.

Obtain the latest image with:

```bash
$ docker pull sigp/lighthouse
```

Download and test the image with:

```bash
$ docker run sigp/lighthouse lighthouse --version
```

If you can see the latest [Lighthouse release](https://github.com/sigp/lighthouse/releases) version
(see example below), then you've successfully installed Lighthouse via Docker.

> Pro tip: try the `latest-modern` image for a 20-30% speed-up! See [Available Docker
> Images](#available-docker-images) below.

### Example Version Output

```
Lighthouse vx.x.xx-xxxxxxxxx
BLS Library: xxxx-xxxxxxx
```

### Available Docker Images

There are several images available on Docker Hub.

Most users should use the `latest-modern` tag, which corresponds to the latest stable release of
Lighthouse with optimizations enabled. If you are running on older hardware then the default
`latest` image bundles a _portable_ version of Lighthouse which is slower but with better hardware
compatibility (see [Portability](./installation-binaries.md#portability)).

To install a specific tag (in this case `latest-modern`) add the tag name to your `docker` commands
like so:

```
$ docker pull sigp/lighthouse:latest-modern
```

Image tags follow this format:

```
${version}${arch}${stability}${modernity}${features}
```

The `version` is:

* `vX.Y.Z` for a tagged Lighthouse release, e.g. `v2.1.1`
* `latest` for the `stable` branch (latest release) or `unstable` branch

The `stability` is:

* `-unstable` for the `unstable` branch
* empty for a tagged release or the `stable` branch

The `arch` is:

* `-amd64` for x86_64, e.g. Intel, AMD
* `-arm64` for aarch64, e.g. Raspberry Pi 4
* empty for a multi-arch image (works on either `amd64` or `arm64` platforms)

The `modernity` is:

* `-modern` for optimized builds
* empty for a `portable` unoptimized build

The `features` is:

* `-dev` for a development build with `minimal-spec` preset enabled.
* empty for a standard build with no custom feature enabled.


Examples:

* `latest-unstable-modern`: most recent `unstable` build for all modern CPUs (x86_64 or ARM)
* `latest-amd64`: most recent Lighthouse release for older x86_64 CPUs
* `latest-amd64-unstable`: most recent `unstable` build for older x86_64 CPUs

## Building the Docker Image

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
$ docker run -p 9000:9000/tcp -p 9000:9000/udp -p 127.0.0.1:5052:5052 -v $HOME/.lighthouse:/root/.lighthouse sigp/lighthouse lighthouse --network mainnet beacon --http --http-address 0.0.0.0
```

> To join the Prater testnet, use `--network prater` instead.

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

In order to be a good peer and serve other peers you should expose port `9000` for both TCP and UDP.
Use the `-p` flag to do this:

```bash
$ docker run -p 9000:9000/tcp -p 9000:9000/udp sigp/lighthouse lighthouse beacon
```

If you use the `--http` flag you may also want to expose the HTTP port with `-p
127.0.0.1:5052:5052`.

```bash
$ docker run -p 9000:9000/tcp -p 9000:9000/udp -p 127.0.0.1:5052:5052 sigp/lighthouse lighthouse beacon --http --http-address 0.0.0.0
```

[docker_hub]: https://hub.docker.com/repository/docker/sigp/lighthouse/
