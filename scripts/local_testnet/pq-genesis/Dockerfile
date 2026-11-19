ARG GO_IMAGE=golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0
ARG GENESIS_IMAGE=ethpandaops/ethereum-genesis-generator:pq@sha256:222c4ebd703c4e22b0f5aaac9aa5aa14a2f8cec45610c27102dbd5bcce19871c

FROM ${GO_IMAGE} AS build
ARG ETH_BEACON_GENESIS_REV=284025a0e819d3a3dfbd8eb20d28f7a8c1ea76a4
WORKDIR /src
RUN git init -q \
    && git fetch -q --depth=1 https://github.com/ethpandaops/eth-beacon-genesis.git "$ETH_BEACON_GENESIS_REV" \
    && git checkout -q --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$ETH_BEACON_GENESIS_REV"
COPY keccak-vrf.patch /keccak-vrf.patch
RUN git apply --unidiff-zero /keccak-vrf.patch \
    && CGO_ENABLED=1 GOTOOLCHAIN=local go build -mod=readonly -trimpath -buildvcs=false \
       -ldflags="-s -w -X github.com/ethpandaops/eth-beacon-genesis/buildinfo.BuildVersion=${ETH_BEACON_GENESIS_REV}-padded-keccak" \
       -o /eth-genesis-state-generator ./cmd/eth-genesis-state-generator

FROM ${GENESIS_IMAGE}
COPY --from=build /eth-genesis-state-generator /usr/local/bin/eth-genesis-state-generator
