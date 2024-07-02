# 📦 Installation

Siren supports Linux, MacOS, and Windows operating systems.

## Version Requirement

To ensure proper functionality, the Siren app requires Lighthouse v4.3.0 or higher. You can find these versions on the [releases](https://github.com/sigp/lighthouse/releases) page of the Lighthouse repository.

## Building From Docker (Recommended)

We recommend using Docker to run Siren, for quicker uptime and installation.

Configuration is done through environment variables, the best way to get started is by copying `.env.example` to `.env` and editing the relevant sections (typically, this would at least include adding `BEACON_URL`, `VALIDATOR_URL` and `API_TOKEN`)

Then to run the image:

`docker compose up`
or
`docker run --rm -ti --name siren -p 3443:443 --env-file $PWD/.env sigp/siren`

This command will open port 3443, allowing your browser to connect.


To start Siren, visit `https://localhost:3443` in your web browser (ignore the certificate warning).

Advanced users can mount their own certificate (the config expects 3 files: `/certs/cert.pem` `/certs/key.pem` `/certs/key.pass`)

## Building From Source

### Docker

The docker image can be built with the following command:
`docker build -f Dockerfile -t siren .`

### Building locally

To build from source, ensure that your system has `Node v18.18` and `yarn` installed. Start by configuring your environment variables. The recommended approach is to duplicate the `.env.example` file, rename it to `.env`, and modify the necessary settings. Essential variables typically include `BEACON_URL`, `VALIDATOR_URL`, and `API_TOKEN`.

#### Build and run the backend
Navigate to the backend directory `cd backend`. Install all required Node packages by running `yarn`. Once the installation is complete, compile the backend with `yarn build`. Deploy the backend in a production environment, `yarn start:production`. This ensures optimal performance.


#### Build and run the frontend
After initializing the backend, return to the root directory. Install all frontend dependencies by executing `yarn`. Build the frontend using `yarn build`. Start the frontend production server with `yarn start`.

This will allow you to access siren at `http://localhost:3000` by default.
