set -Eeuo pipefail

source ./vars.env

# Get options
while getopts "d:sh" flag; do
  case "${flag}" in
    d) DEBUG_LEVEL=${OPTARG};;
    s) SUBSCRIBE_ALL_SUBNETS="--subscribe-all-subnets";;
    h)
       echo "Start a geth node"
       echo
       echo "usage: $0 <Options> <DATADIR> <NETWORK-PORT> <HTTP-PORT>"
       echo
       echo "Options:"
       echo "   -h: this help"
       echo
       echo "Positional arguments:"
       echo "  DATADIR       Value for --datadir parameter"
       echo "  NETWORK-PORT  Value for --port"
       echo "  HTTP-PORT     Value for --http.port"
       echo "  AUTH-PORT     Value for --authrpc.port"
       echo "  GENESIS_FILE  Value for geth init"
       exit
       ;;
  esac
done

# Get positional arguments
data_dir=${@:$OPTIND+0:1}
network_port=${@:$OPTIND+1:1}
http_port=${@:$OPTIND+2:1}
auth_port=${@:$OPTIND+3:1}
genesis_file=${@:$OPTIND+4:1}

geth_binary=geth-merge

# Init
$geth_binary init \
    --datadir $data_dir \
    $genesis_file

echo "Completed init"

exec $geth_binary \
    --datadir $data_dir \
    --ipcdisable \
    --http \
    --http.api="engine,eth,web3,net,debug" \
    --networkid=$CHAIN_ID \
    --syncmode=full \
    --bootnodes $EL_BOOTNODE_ENODE \
    --port $network_port \
    --http.port $http_port \
    --authrpc.port $auth_port