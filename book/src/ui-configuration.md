# Configuration

The Lighthouse UI requires a connection to both a Lighthouse Validator Client
and a Lighthouse Beacon Node. Upon running you will first be greeted by the
following configuration screen.

![ui-configuration](./imgs/ui-configuration.png)





## Pre-Built Electron Packages

There are pre-compiled electron packages for each operating systems which can
be downloaded and executed. These can be found on the
[releases](https://github.com/sigp/lighthouse-ui/releases) page of the
Lighthouse UI repository.

Simply download the package specific to your operating system and run it.

## Building From Source

### Requirements

Building from source requires `Node v16.16.0` and `yarn`. 

### Building From Source

The electron app can be built from source by first cloning the repository:

```
$ git clone https://github.com/sigp/lighthouse-ui.git
```

Once cloned, the required packages need to be downloaded:

```
$ cd lighthouse-ui
$ yarn
```

Once completed successfully the electron app can be built and executed via:

```
$ yarn dev
```

#### Running In The Browser

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
