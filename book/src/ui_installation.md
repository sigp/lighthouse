# 📦 Installation

Siren supports any operating system that supports containers and/or NodeJS 18, this includes Linux, MacOS, and Windows. The recommended way of running Siren is by launching the [docker container](https://hub.docker.com/r/sigp/siren).

## Version Requirement

To ensure proper functionality, the Siren app requires Lighthouse v4.3.0 or higher. You can find these versions on the [releases](https://github.com/sigp/lighthouse/releases) page of the Lighthouse repository.

## Configuration

Siren requires a connection to both a Lighthouse Validator Client and a Lighthouse Beacon Node.

Both the Beacon node and the Validator client need to have their HTTP APIs enabled.
These ports should be accessible from Siren. This means adding the flag `--http` on both beacon node and validator client.

To enable the HTTP API for the beacon node, utilize the `--gui` CLI flag. This action ensures that the HTTP API can be accessed by other software on the same machine. It also enables the validator monitoring.

> The Beacon Node must be run with the `--gui` flag set.

## Running Siren with Docker Compose (Recommended)

We recommend running Siren's container next to your beacon node (on the same server), as it's essentially a webapp that you can access with any browser.

 1. Clone the Siren repository:

    ```
    git clone https://github.com/sigp/siren
    cd siren
    ```

 1. Copy the example `.env.example` file to `.env`:

    ```
    cp .env.example .env
    ```

 1. Edit the `.env` file filling in the required fields. A beacon node and validator url needs to be
    specified as well as the validator clients `API_TOKEN`, which can be obtained from the [`Validator Client Authorization Header`](./api_vc_auth_header.md).
    Note that the HTTP API ports must be accessible from within docker and cannot just be listening
    on localhost. This means using the
 `--http-address 0.0.0.0` flag on the beacon node and, and both `--http-address 0.0.0.0` and `--unencrypted-http-transport` flags on the validator client.

 1. Run the containers with docker compose

    ```
    docker compose up -d
    ```

 1. You should now be able to access siren at the url (provided SSL is enabled):

    ```
    https://localhost
    ```

> Note: If running on a remote host and the port is exposed, you can access Siren remotely via
`https://<IP-OF-REMOTE-HOST>`

## Running Siren in Docker

 1. Create a directory to run Siren:

    ```bash
    cd ~
    mkdir Siren
    cd Siren
    ```

 1. Create a configuration file in the `Siren` directory: `nano .env` and insert the following fields to the `.env` file. The field values are given here as an example, modify the fields as necessary. For example, the `API_TOKEN` can be obtained from [`Validator Client Authorization Header`](./api_vc_auth_header.md).

    A full example with all possible configuration options can be found [here](https://github.com/sigp/siren/blob/stable/.env.example).

    ```
    BEACON_URL=http://localhost:5052
    VALIDATOR_URL=http://localhost:5062
    API_TOKEN=R6YhbDO6gKjNMydtZHcaCovFbQ0izq5Hk
    SESSION_PASSWORD=your_password
    ```

 1. You can now start Siren with:

    ```bash
    docker run -ti --name siren --env-file $PWD/.env -p 443:443 sigp/siren
    ```

> Note: If you have only exposed your HTTP API ports on the Beacon Node and Validator client to
localhost, i.e via --http-address 127.0.0.1, you must add
`--add-host=host.docker.internal:host-gateway` to the docker command to allow docker to access the
hosts localhost. Alternatively, you should expose the HTTP API to the IP address of the host or
`0.0.0.0`

 1. Siren should be accessible at the url:

    ```
    https://localhost
    ```

> Note: If running on a remote host and the port is exposed, you can access Siren remotely via
`https://<IP-OF-REMOTE-HOST>`

## Possible Docker Errors

Note that when use SSL, you will get an SSL warning. Advanced users can mount their own certificates or disable SSL altogether, see the `SSL Certificates` section below. This error is safe to ignore.

If it fails to start, an error message will be shown. For example, the error

```
http://localhost:5062 unreachable, check settings and connection
```

means that the validator client is not running, or the `--http` flag is not provided, or otherwise inaccessible from within the container. Another common error is:

```
validator api issue, server response: 403
```

which means that the API token is incorrect. Check that you have provided the correct token in the field `API_TOKEN` in `.env`.

When Siren has successfully started, you should see the log `LOG [NestApplication] Nest application successfully started +118ms`, indicating that Siren has started (in the docker logs).

> Note: We recommend setting a strong password when running Siren to protect it from unauthorized access.

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

By default, internally, Siren is running on port 80 (plain, behind nginx), port 3000 (plain, direct) and port 443 (with SSL, behind nginx)). Siren will generate and use a self-signed certificate on startup. This will generate a security warning when you try to access the interface. We recommend to only disable SSL if you would access Siren over a local LAN or otherwise highly trusted or encrypted network (i.e. VPN).

#### Generating persistent SSL certificates and installing them to your system

[mkcert](https://github.com/FiloSottile/mkcert) is a tool that makes it super easy to generate a self-signed certificate that is trusted by your browser.

To use it for `siren`, install it following the instructions. Then, run `mkdir certs; mkcert -cert-file certs/cert.pem -key-file certs/key.pem 127.0.0.1 localhost` (add or replace any IP or hostname that you would use to access it at the end of this command).
To use these generated certificates, add this to to your `docker run` command: `-v $PWD/certs:/certs`

The nginx SSL config inside Siren's container expects 3 files: `/certs/cert.pem` `/certs/key.pem` `/certs/key.pass`. If `/certs/cert.pem` does not exist, it will generate a self-signed certificate as mentioned above. If `/certs/cert.pem` does exist, it will attempt to use your provided or persisted certificates.

### Configuration through environment variables

For those who prefer to use environment variables to configure Siren instead of using an `.env` file, this is fully supported. In some cases this may even be preferred.

#### Docker installed through `snap`

If you installed Docker through a snap (i.e. on Ubuntu), Docker will have trouble accessing the `.env` file. In this case it is highly recommended to pass the config to the container with environment variables.
Note that the defaults in `.env.example` will be used as fallback, if no other value is provided.
