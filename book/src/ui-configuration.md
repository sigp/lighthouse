# 📦 Installation

Siren supports any operating system that supports container runtimes and/or NodeJS 18, this includes Linux, MacOS, and Windows. The recommended way of running Siren is by launching the [docker container](https://hub.docker.com/r/sigp/siren).

## Version Requirement

To ensure proper functionality, the Siren app requires Lighthouse v4.3.0 or higher. You can find these versions on the [releases](https://github.com/sigp/lighthouse/releases) page of the Lighthouse repository.

## Configuration

Siren requires a connection to both a Lighthouse Validator Client and a Lighthouse Beacon Node.  

Both the Beacon node and the Validator client need to have their HTTP APIs enabled.  
These ports should be accessible from Siren. This means adding the flag `--http` on both beacon node and validator client.

To enable the HTTP API for the beacon node, utilize the `--gui` CLI flag. This action ensures that the HTTP API can be accessed by other software on the same machine.

> The Beacon Node must be run with the `--gui` flag set.

## Running the Docker container (Recommended)

The common usage is to run Siren at a client computer connecting to a server running the node. The following guide is to setup Siren at a client computer and connect it to the server via SSH, so that Siren can be accessed and viewed from the client computer's browser.

 1. Create a directory to run Siren:

    ```bash
    cd ~
    mkdir Siren
    cd Siren
    ```

 1. Create a configuration file in the `Siren` directory: `nano .env` and insert the following fields to the `.env` file. The field values are given here as an example, modify the fields as necessary. For example, the `API_TOKEN` can be obtained from [`Validator Authorization`](./api-vc-auth-header.md):
    ```
    BEACON_URL=http://localhost:5052
    VALIDATOR_URL=http://localhost:5062
    API_TOKEN=R6YhbDO6gKjNMydtZHcaCovFbQ0izq5Hk
    SESSION_PASSWORD=your_password
    ```

 1. You can now start Siren with:
    ```bash
    docker run --rm -ti --name siren -p 4443:443 --env-file $PWD/.env --net host sigp/siren
    ```
    If it fails to start, an error message will be shown. For example, the error
    ```
    http://localhost:5062 unreachable, check settings and connection
    ```
    means that the validator client is not running, or the `--http` flag is not provided. Another common error is:
    ```
    validator api issue, server response: 403
    ```
    which means that the API token is incorrect. Check that you have provided the correct token in the field `API_TOKEN` in `.env`.

    When Siren is successfully run, you should see the log `LOG [NestApplication] Nest application successfully started +118ms`, indicating that Siren has started. 

 1. At the client computer, SSH to the server:
    ```bash
    ssh -L 3000:127.0.0.1:3000  username@server_IP
    ```
    You can now access siren by entering `localhost:3000` to a browser in the client computer. 


Advanced users can mount their own certificates, see the `SSL Certificates` section below

## Building From Source

### Docker

The docker image can be built with the following command:
`docker build -f Dockerfile -t siren .`

### Building locally

To build from source, ensure that your system has `Node v18.18` and `yarn` installed.

#### Build and run the backend

Navigate to the backend directory `cd backend`. Install all required Node packages by running `yarn`. Once the installation is complete, compile the backend with `yarn build`. Deploy the backend in a production environment, `yarn start:production`. This ensures optimal performance.

#### Build and run the frontend

After initializing the backend, return to the root directory. Install all frontend dependencies by executing `yarn`. Build the frontend using `yarn build`. Start the frontend production server with `yarn start`.

This will allow you to access siren at `http://localhost:3000` by default.

## Advanced configuration

### About self-signed SSL certificates

By default, Siren will generate and use a self-signed certificate on startup.
This will generate a security warning when you try to access the interface.
We recommend to only disable SSL if you would access Siren over a local LAN or otherwise highly trusted or encrypted network (i.e. VPN).

#### Generating persistent SSL certificates and installing them to your system

[mkcert](https://github.com/FiloSottile/mkcert) is a tool that makes it super easy to generate a self-signed certificate that is trusted by your browser.

To use it for `siren`, install it following the instructions. Then, run `mkdir certs; mkcert -cert-file certs/cert.pem -key-file certs/key.pem 127.0.0.1 localhost` (add or replace any IP or hostname that you would use to access it at the end of this command)

The nginx SSL config inside Siren's container expects 3 files: `/certs/cert.pem` `/certs/key.pem` `/certs/key.pass`. If `/certs/cert.pem` does not exist, it will generate a self-signed certificate as mentioned above. If `/certs/cert.pem` does exist, it will attempt to use your provided or persisted certificates.

### Configuration through environment variables

For those who prefer to use environment variables to configure Siren instead of using an `.env` file, this is fully supported. In some cases this may even be preferred.

#### Docker installed through `snap`

If you installed Docker through a snap (i.e. on Ubuntu), Docker will have trouble accessing the `.env` file. In this case it is highly recommended to pass the config to the container with environment variables.
Note that the defaults in `.env.example` will be used as fallback, if no other value is provided.
