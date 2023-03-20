# 📦 Installation

Siren runs on Linux, MacOS and Windows.

## Version Requirement
The Siren app requires Lighthouse v3.5.1 or higher to function properly. These versions can be found on the [releases](https://github.com/sigp/lighthouse/releases) page of the Lighthouse repository.

## Pre-Built Electron Packages

There are pre-compiled electron packages for each operating systems which can
be downloaded and executed. These can be found on the
[releases](https://github.com/sigp/siren/releases) page of the
Siren repository.

Simply download the package specific to your operating system and run it.

## Building From Source

### Requirements

Building from source requires `Node v18` and `yarn`.

### Building From Source

The electron app can be built from source by first cloning the repository and
entering the directory:

```
$ git clone https://github.com/sigp/siren.git
$ cd siren
```

Once cloned, the electron app can be built and ran via the Makefile by:

```
$ make
```

alternatively it can be built via:

```
$ yarn
```

Once completed successfully the electron app can be run via:

```
$ yarn dev
```

### Running In The Browser

#### Docker (Recommended)

Docker is the recommended way to run a webserver that hosts Siren and can be
connected to via a web browser. We recommend this method as it establishes a
production-grade web-server to host the application.

`docker` is required to be installed with the service running.

The docker image can be built and run via the Makefile by running:
```
$ make docker
```

Alternatively, to run with Docker, the image needs to be built. From the repository directory
run:
```
$ docker build -t siren .
```

Then to run the image:
```
$ docker run --rm -ti --name siren -p 80:80 siren
```

This will open port 80 and allow your browser to connect. You can choose
another local port by modifying the command. For example `-p 8000:80` will open
port 8000.

To view Siren, simply go to `http://localhost` in your web browser.

#### Development Server

A development server can also be built which will expose a local port 3000 via:
```
$ yarn start
```

Once executed, you can direct your web browser to the following URL to interact
with the app:
```
http://localhost:3000
```

A production version of the app can be built via
```
$ yarn build
```
and then further hosted via a production web server.

### Known Issues

If you experience any issues in running the UI please create an issue on the
[Lighthouse UI](https://github.com/sigp/lighthouse-ui) repository.
