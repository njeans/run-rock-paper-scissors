# Run rockpaperscissors chaincode

## Repos:
- [https://github.com/hybridNeo/honeybadgerscc](https://github.com/hybridNeo/honeybadgerscc) 
    - system chaincode for honeybadgermpc.
    - Instructions:
        - Update `script.sh` to changes below [script.sh](#honeybadgerscc-script)
        - Create new file  `script-peer.sh` [script-peer.sh](#honeybadgerscc-script-peer)
        - Run commands below
```
./script.sh 
./script-peer.sh 
```

- [https://github.com/hybridNeo/fabric/tree/e2e-stash](https://github.com/hybridNeo/fabric/tree/e2e-stash)
    - fork of hyperledger/fabric updated dockerfiles of fabric-peer to support HBMPC. clone this and make to build everything necessary.
    - Instructions:
        - Update `images/peer/Dockerfile.in` to changes below [Dockerfile.in](#Dockerfile)
        - Run commands below
```
export DOCKER_DYNAMIC_LINK=true 
export GO_TAGS+=" pluginsenabled"  
make peer-docker 
``` 

- [https://github.com/hybridNeo/fabric-test](https://github.com/hybridNeo/fabric-test)
    - This contains the chaincodes we used for testing i.e rockpaperscissors, auction and linear regression. use first-network in this to run the peers, orderer etc.
    - Instructions:
        - Update `fabric-test/scripts/script.sh`  to changes below [script.sh](#fabric-test-script)
        - Update `fabric-test/scripts/utils.sh` to changes below [utils.sh](#fabric-test-utils)
        - Go to `fabric-test` folder
        - Run commands below
```
./byfn.sh generate 
./byfn.sh up 
```

- [https://github.com/hybridNeo/HoneyBadgerMPC/tree/dev](https://github.com/hybridNeo/HoneyBadgerMPC/tree/dev)
    - Fork of honeybadgermpc not up to date with initc3 version. Need to figure out a strategy to get it up to date. it has client scripts and fabric related code. 
    - https://github.com/hybridNeo/sharedata
    - Since we did not have offline phase at the time of experiments, this is like a hacky way to get pre-processing. just pull it in the peers if they do not exist already. (We now have offline_randousha).

If build fails go to hybridNeo/fabric-test repo on branch release-1.4 and run scripts/bootstrap.sh

## Updated/New Files:
### honeybadgerscc script 
- Repo: https://github.com/hybridNeo/honeybadgerscc   
- File: script.sh 
- Changes: change hardcoded path to using the $GOPATH environment variable
```
docker run -it --rm \
    -v $GOPATH/src/github.com/hybridNeo/honeybadgerscc:/opt/gopath/src/github.com/hybridNeo/honeybadgerscc \
    -w /opt/gopath/src/github.com/hybridNeo/honeybadgerscc \
    -v $GOPATH/src/github.com/hyperledger/fabric:/opt/gopath/src/github.com/hyperledger/fabric \
    -v $GOPATH/src/github.com/hybridNeo/honeybadgerscc/.build/docker/bin:/opt/gopath/bin \
    -v $GOPATH/src/github.com/hybridNeo/honeybadgerscc/.build/docker/pkg:/opt/gopath/pkg \
    -v $GOPATH/src/github.com/syndtr/goleveldb:/opt/gopath/src/github.com/syndtr/goleveldb \
    -v $GOPATH/src/github.com/golang/snappy:/opt/gopath/src/github.com/golang/snappy \
    hyperledger/fabric-baseimage:amd64-0.4.13 \
    go build -buildmode=plugin -tags ""
```
### honeybadgerscc script peer 
- Repo: https://github.com/hybridNeo/honeybadgerscc   
- File: script-peer.sh 
- Changes: build the peer in the Dockerfile in order for it to have the same packages as the plugin (system chaincode). 
       - This requirement is mentioned on this page of hyperledger docs under "Developing Plugins" second paragraph.  
       - https://hyperledger-fabric.readthedocs.io/en/release-1.4/systemchaincode.html#developing-plugins
```
docker run -it --rm \
    -v $GOPATH:/opt/gopath \
    -w /opt/gopath/src/github.com/hyperledger/fabric \
    -e GO_TAGS=" pluginsenabled" \
    hyperledger/fabric-baseimage:amd64-0.4.13 \
    bash -c "apt-get update && apt-get install -y --no-install-recommends build-essential && make peer"
```
### Dockerfile
- Repo: https://github.com/hybridNeo/fabric/tree/e2e-stash
- File: images/peer/Dockerfile.in 
- Install dependencies for HoneyBadgerMPC
```
# Copyright Greg Haskins All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0
#
FROM _BASE_NS_/fabric-baseos:_BASE_TAG_
ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
RUN mkdir -p /var/hyperledger/production $FABRIC_CFG_PATH
COPY payload/peer /usr/local/bin
ADD  payload/sampleconfig.tar.bz2 $FABRIC_CFG_PATH
# BEGIN: Python HoneyBadgerMPC dependencies
# Install apt dependencies
# Put apt dependencies here that are needed by all build paths
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    iproute2 \
    libflint-dev \
    libgmp-dev \
    libffi-dev \
    libmpc-dev \
    libmpfr-dev \
    libssl-dev \
    openssl \
    sudo \
    bison \
    cmake \
    flex \
    wget
# Install Python3.7
WORKDIR /
RUN wget https://www.python.org/ftp/python/3.7.4/Python-3.7.4.tgz
RUN tar xzf Python-3.7.4.tgz
WORKDIR /Python-3.7.4
RUN ./configure --enable-optimizations
RUN make -j 1
RUN make altinstall
# Re-install pip3
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python3.7 get-pip.py --force-reinstall
# Allows for log messages to be immediately dumped to the
# stream instead of being buffered.
ENV PYTHONUNBUFFERED 1
# Path variables needed for Charm
ENV LIBRARY_PATH /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib
ENV LIBRARY_INCLUDE_PATH /usr/local/include
# Setup virtualenv
ENV PYTHON_LIBRARY_PATH /opt/venv
ENV PATH ${PYTHON_LIBRARY_PATH}/bin:${PATH}
RUN pip3 install virtualenv
ENV PYTHON_LIBRARY_PATH /opt/venv
ENV PATH ${PYTHON_LIBRARY_PATH}/bin:${PATH}
RUN python3.7 -m virtualenv ${PYTHON_LIBRARY_PATH}
RUN virtualenv -p /usr/local/bin/python3.7 ${PYTHON_LIBRARY_PATH}
# python dependencies
RUN pip3 install \
    cffi \
    Cython \
    gmpy2 \
    psutil \
    pycrypto \
    pyzmq \
    zfec
# This is needed otherwise the build for the power sum solver will fail.
# This is a known issue in the version of libflint-dev in apt.
# https://github.com/wbhart/flint2/issues/217
# This has been fixed if we pull the latest code from the repo. However, we want
# to avoid compiling the lib from the source since it adds 20 minutes to the build.
RUN sed -i '30c #include "flint/flint.h"' /usr/include/flint/flintxx/flint_classes.h
WORKDIR /
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2018-10-24
ENV PATH "/root/.cargo/bin:${PATH}"
# # Install NTL
# WORKDIR /
# RUN curl -so - https://www.shoup.net/ntl/ntl-11.3.2.tar.gz | tar xzvf -
# WORKDIR /ntl-11.3.2/src
# RUN ./configure CXXFLAGS="-g -O2 -fPIC -march=native -pthread -std=c++11"
# RUN make
# RUN make install
#
# # Install better pairing
# # Creates dependencies in /usr/local/include/pbc and /usr/local/lib
# WORKDIR /
# RUN curl -so - https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz | tar xzvf -
# WORKDIR /pbc-0.5.14/
# RUN ./configure
# RUN make
# RUN make install
#
# # Install charm
# # Creates /charm/dist/Charm_Crypto...x86_64.egg, which gets copied into the venv
# # /opt/venv/lib/python3.7/site-packages/Charm_crypto...x86_64.egg
# WORKDIR /
# RUN git clone https://github.com/JHUISI/charm.git
# WORKDIR /charm
# RUN git reset --hard be9587ccdd4d61c591fb50728ebf2a4690a2064f
# RUN ./configure.sh
# RUN make install
# RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
#    locale-gen
# ENV LANG en_US.UTF-8
# ENV LANGUAGE en_US:en
# ENV LC_ALL en_US.UTF-8
# # Install solidity
# RUN git clone --recursive https://github.com/ethereum/solidity.git
# WORKDIR /solidity/
# RUN git checkout v0.4.24 # Old version necessary to work???
# RUN git submodule update --init --recursive
# RUN ./scripts/install_deps.sh
# RUN mkdir build/
# WORKDIR /solidity/build/
# RUN cmake ..
# RUN make install
# WORKDIR /
# clone and install HoneyBadgerMPC
WORKDIR /usr/src
RUN git clone https://github.com/initc3/HoneyBadgerMPC.git
RUN pip3 install HoneyBadgerMPC
# install pairing
WORKDIR /usr/src/HoneyBadgerMPC
RUN pip3 install pairing/
CMD ["peer","node","start"]
```
### fabric test script
- Repo: https://github.com/hybridNeo/fabric-test
- File: fabric-test/scripts/script.sh
- Changes: Make the script install the rockpaperscissors chaincode found in `chaincode/rockpaperscissors`, Add commands that will call the rockpaperscissors chaincode
```
#!/bin/bash

echo
echo " ____    _____      _      ____    _____ "
echo "/ ___|  |_   _|    / \    |  _ \  |_   _|"
echo "\___ \    | |     / _ \   | |_) |   | |  "
echo " ___) |   | |    / ___ \  |  _ <    | |  "
echo "|____/    |_|   /_/   \_\ |_| \_\   |_|  "
echo
echo "Build your first network (BYFN) end-to-end test"
echo
CHANNEL_NAME="$1"
DELAY="$2"
LANGUAGE="$3"
TIMEOUT="$4"
VERBOSE="$5"
: ${CHANNEL_NAME:="mychannel"}
: ${DELAY:="3"}
: ${LANGUAGE:="golang"}
: ${TIMEOUT:="10"}
: ${VERBOSE:="false"}
LANGUAGE=`echo "$LANGUAGE" | tr [:upper:] [:lower:]`
COUNTER=1
MAX_RETRY=10

CC_SRC_PATH="github.com/chaincode/rockpaperscissors/"

echo "Channel name : "$CHANNEL_NAME

# import utils
. scripts/utils.sh

createChannel() {
	setGlobals 0 1

	if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
                set -x
		peer channel create -o orderer.example.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/channel.tx >&log.txt
		res=$?
                set +x
	else
				set -x
		peer channel create -o orderer.example.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/channel.tx --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA >&log.txt
		res=$?
				set +x
	fi
	cat log.txt
	verifyResult $res "Channel creation failed"
	echo "===================== Channel '$CHANNEL_NAME' created ===================== "
	echo
}

joinChannel () {
	for org in 1 2; do
	    for peer in 0 1; do
		joinChannelWithRetry $peer $org
		echo "===================== peer${peer}.org${org} joined channel '$CHANNEL_NAME' ===================== "
		sleep $DELAY
		echo
	    done
	done
}

## Create channel
echo "Creating channel..."
createChannel

## Join all the peers to the channel
echo "Having all peers join the channel..."
joinChannel

## Set the anchor peers for each org in the channel
echo "Updating anchor peers for org1..."
updateAnchorPeers 0 1
echo "Updating anchor peers for org2..."
updateAnchorPeers 0 2

## Install chaincode on peer0.org1 and peer0.org2
echo "Installing chaincode on peer0.org1..."
installChaincode 0 1
echo "Install chaincode on peer0.org2..."
installChaincode 0 2

# Instantiate chaincode on peer0.org2
echo "Instantiating chaincode on peer0.org2..."
instantiateChaincode 0 2

# Instantiate chaincode on peer0.org2
echo "Instantiating chaincode on peer0.org1..."
instantiateChaincode 0 1
sleep 1

echo "getActiveGames chaincode on peer0.org2... should be empty"
getActiveGames 0 2

echo "createGame chaincode on peer0.org1..."
createGame 0 1
sleep 1
echo "getActiveGames chaincode on peer0.org2... should be game1"
getActiveGames 0 2

echo "getActiveGames chaincode on peer0.org1... should be game1"
getActiveGames 0 1

echo "joinGame on peer0.org2..."
joinGame 0 2

echo "openMoves chaincode on peer0.org1..."
openMoves 0 1

echo "openMoves chaincode on peer0.org2..."
openMoves 0 2

echo "endGame on peer0.org2..."
endGame 0 2

echo "endGame on peer0.org1..."
endGame 0 1

echo "getCompletedGames chaincode on peer0.org1..."
getCompletedGames 0 1

echo
echo "========= All GOOD, BYFN execution completed =========== "
echo

echo
echo " _____   _   _   ____   "
echo "| ____| | \ | | |  _ \  "
echo "|  _|   |  \| | | | | | "
echo "| |___  | |\  | | |_| | "
echo "|_____| |_| \_| |____/  "
echo

exit 0
```

### fabric test utils
- Repo: https://github.com/hybridNeo/fabric-test
- File: fabric-test/scripts/utils.sh
- Changes: Add commands that will can invoke chaincode functions
``` 
#
# Copyright IBM Corp All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0
#

# This is a collection of bash functions used by different scripts

ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
PEER0_ORG1_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
PEER0_ORG2_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
PEER0_ORG3_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt

CC_NAME=rpscc
# verify the result of the end-to-end test
verifyResult() {
  if [ $1 -ne 0 ]; then
    echo "!!!!!!!!!!!!!!! "$2" !!!!!!!!!!!!!!!!"
    echo "========= ERROR !!! FAILED to execute End-2-End Scenario ==========="
    echo
    exit 1
  fi
}

# Set OrdererOrg.Admin globals
setOrdererGlobals() {
  CORE_PEER_LOCALMSPID="OrdererMSP"
  CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
  CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/users/Admin@example.com/msp
}

setGlobals() {
  PEER=$1
  ORG=$2
  if [ $ORG -eq 1 ]; then
    CORE_PEER_LOCALMSPID="Org1MSP"
    CORE_PEER_TLS_ROOTCERT_FILE=$PEER0_ORG1_CA
    CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
    if [ $PEER -eq 0 ]; then
      CORE_PEER_ADDRESS=peer0.org1.example.com:7051
    else
      CORE_PEER_ADDRESS=peer1.org1.example.com:7051
    fi
  elif [ $ORG -eq 2 ]; then
    CORE_PEER_LOCALMSPID="Org2MSP"
    CORE_PEER_TLS_ROOTCERT_FILE=$PEER0_ORG2_CA
    CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
    if [ $PEER -eq 0 ]; then
      CORE_PEER_ADDRESS=peer0.org2.example.com:7051
    else
      CORE_PEER_ADDRESS=peer1.org2.example.com:7051
    fi

  elif [ $ORG -eq 3 ]; then
    CORE_PEER_LOCALMSPID="Org3MSP"
    CORE_PEER_TLS_ROOTCERT_FILE=$PEER0_ORG3_CA
    CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp
    if [ $PEER -eq 0 ]; then
      CORE_PEER_ADDRESS=peer0.org3.example.com:7051
    else
      CORE_PEER_ADDRESS=peer1.org3.example.com:7051
    fi
  else
    echo "================== ERROR !!! ORG Unknown =================="
  fi

  if [ "$VERBOSE" == "true" ]; then
    env | grep CORE
  fi
}

updateAnchorPeers() {
  PEER=$1
  ORG=$2
  setGlobals $PEER $ORG

  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer channel update -o orderer.example.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/${CORE_PEER_LOCALMSPID}anchors.tx >&log.txt
    res=$?
    set +x
  else
    set -x
    peer channel update -o orderer.example.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/${CORE_PEER_LOCALMSPID}anchors.tx --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Anchor peer update failed"
  echo "===================== Anchor peers updated for org '$CORE_PEER_LOCALMSPID' on channel '$CHANNEL_NAME' ===================== "
  sleep $DELAY
  echo
}

## Sometimes Join takes time hence RETRY at least 5 times
joinChannelWithRetry() {
  PEER=$1
  ORG=$2
  setGlobals $PEER $ORG

  set -x
  peer channel join -b $CHANNEL_NAME.block >&log.txt
  res=$?
  set +x
  cat log.txt
  if [ $res -ne 0 -a $COUNTER -lt $MAX_RETRY ]; then
    COUNTER=$(expr $COUNTER + 1)
    echo "peer${PEER}.org${ORG} failed to join the channel, Retry after $DELAY seconds"
    sleep $DELAY
    joinChannelWithRetry $PEER $ORG
  else
    COUNTER=1
  fi
  verifyResult $res "After $MAX_RETRY attempts, peer${PEER}.org${ORG} has failed to join channel '$CHANNEL_NAME' "
}

installChaincode() {
  PEER=$1
  ORG=$2
  setGlobals $PEER $ORG
  VERSION=${3:-1.0}
  set -x
  peer chaincode install -n $CC_NAME -v ${VERSION} -l ${LANGUAGE} -p ${CC_SRC_PATH} >&log.txt
  res=$?
  set +x
  cat log.txt
  verifyResult $res "Chaincode installation on peer${PEER}.org${ORG} has failed"
  echo "===================== Chaincode is installed on peer${PEER}.org${ORG} ===================== "
  echo
}

instantiateChaincode() {
  PEER=$1
  ORG=$2
  setGlobals $PEER $ORG
  VERSION=${3:-1.0}

  # while 'peer chaincode' command can get the orderer endpoint from the peer
  # (if join was successful), let's supply it directly as we know it using
  # the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode instantiate -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME -l ${LANGUAGE} -v ${VERSION} -c '{"Args":["init"]}' -P "OR ('Org1MSP.peer','Org2MSP.peer')" >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode instantiate -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME -l ${LANGUAGE} -v 1.0 -c '{"Args":["init"]}' -P "OR ('Org1MSP.peer','Org2MSP.peer')" >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Chaincode instantiation on peer${PEER}.org${ORG} on channel '$CHANNEL_NAME' failed"
  echo "===================== Chaincode is instantiated on peer${PEER}.org${ORG} on channel '$CHANNEL_NAME' ===================== "
  echo
}

upgradeChaincode() {
  PEER=$1
  ORG=$2
  setGlobals $PEER $ORG

  set -x
  peer chaincode upgrade -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME -v 2.0 -c '{"Args":["init","a","90","b","210"]}' -P "AND ('Org1MSP.peer','Org2MSP.peer','Org3MSP.peer')"
  res=$?
  set +x
  cat log.txt
  verifyResult $res "Chaincode upgrade on peer${PEER}.org${ORG} has failed"
  echo "===================== Chaincode is upgraded on peer${PEER}.org${ORG} on channel '$CHANNEL_NAME' ===================== "
  echo
}

chaincodeQuery() {
  PEER=$1
  ORG=$2
  setGlobals $PEER $ORG
  EXPECTED_RESULT=$3
  echo "===================== Querying on peer${PEER}.org${ORG} on channel '$CHANNEL_NAME'... ===================== "
  local rc=1
  local starttime=$(date +%s)

  # continue to poll
  # we either get a successful response, or reach TIMEOUT
  while
    test "$(($(date +%s) - starttime))" -lt "$TIMEOUT" -a $rc -ne 0
  do
    sleep $DELAY
    echo "Attempting to Query peer${PEER}.org${ORG} ...$(($(date +%s) - starttime)) secs"
    set -x
    peer chaincode query -C $CHANNEL_NAME -n $CC_NAME -c '{"Args":["query","a"]}' >&log.txt
    res=$?
    set +x
    test $res -eq 0 && VALUE=$(cat log.txt | awk '/Query Result/ {print $NF}')
    test "$VALUE" = "$EXPECTED_RESULT" && let rc=0
    # removed the string "Query Result" from peer chaincode query command
    # result. as a result, have to support both options until the change
    # is merged.
    test $rc -ne 0 && VALUE=$(cat log.txt | egrep '^[0-9]+$')
    test "$VALUE" = "$EXPECTED_RESULT" && let rc=0
  done
  echo
  cat log.txt
  if test $rc -eq 0; then
    echo "===================== Query successful on peer${PEER}.org${ORG} on channel '$CHANNEL_NAME' ===================== "
  else
    echo "!!!!!!!!!!!!!!! Query result on peer${PEER}.org${ORG} is INVALID !!!!!!!!!!!!!!!!"
    echo "================== ERROR !!! FAILED to execute End-2-End Scenario =================="
    echo
    exit 1
  fi
}

# fetchChannelConfig <channel_id> <output_json>
# Writes the current channel config for a given channel to a JSON file
fetchChannelConfig() {
  CHANNEL=$1
  OUTPUT=$2

  setOrdererGlobals

  echo "Fetching the most recent configuration block for the channel"
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer channel fetch config config_block.pb -o orderer.example.com:7050 -c $CHANNEL --cafile $ORDERER_CA
    set +x
  else
    set -x
    peer channel fetch config config_block.pb -o orderer.example.com:7050 -c $CHANNEL --tls --cafile $ORDERER_CA
    set +x
  fi

  echo "Decoding config block to JSON and isolating config to ${OUTPUT}"
  set -x
  configtxlator proto_decode --input config_block.pb --type common.Block | jq .data.data[0].payload.data.config >"${OUTPUT}"
  set +x
}

# signConfigtxAsPeerOrg <org> <configtx.pb>
# Set the peerOrg admin of an org and signing the config update
signConfigtxAsPeerOrg() {
  PEERORG=$1
  TX=$2
  setGlobals 0 $PEERORG
  set -x
  peer channel signconfigtx -f "${TX}"
  set +x
}

# createConfigUpdate <channel_id> <original_config.json> <modified_config.json> <output.pb>
# Takes an original and modified config, and produces the config update tx
# which transitions between the two
createConfigUpdate() {
  CHANNEL=$1
  ORIGINAL=$2
  MODIFIED=$3
  OUTPUT=$4

  set -x
  configtxlator proto_encode --input "${ORIGINAL}" --type common.Config >original_config.pb
  configtxlator proto_encode --input "${MODIFIED}" --type common.Config >modified_config.pb
  configtxlator compute_update --channel_id "${CHANNEL}" --original original_config.pb --updated modified_config.pb >config_update.pb
  configtxlator proto_decode --input config_update.pb --type common.ConfigUpdate >config_update.json
  echo '{"payload":{"header":{"channel_header":{"channel_id":"'$CHANNEL'", "type":2}},"data":{"config_update":'$(cat config_update.json)'}}}' | jq . >config_update_in_envelope.json
  configtxlator proto_encode --input config_update_in_envelope.json --type common.Envelope >"${OUTPUT}"
  set +x
}

# parsePeerConnectionParameters $@
# Helper function that takes the parameters from a chaincode operation
# (e.g. invoke, query, instantiate) and checks for an even number of
# peers and associated org, then sets $PEER_CONN_PARMS and $PEERS
parsePeerConnectionParameters() {
  # check for uneven number of peer and org parameters
  if [ $(($# % 2)) -ne 0 ]; then
    exit 1
  fi

  PEER_CONN_PARMS=""
  PEERS=""
  while [ "$#" -gt 0 ]; do
    PEER="peer$1.org$2"
    PEERS="$PEERS $PEER"
    PEER_CONN_PARMS="$PEER_CONN_PARMS --peerAddresses $PEER.example.com:7051"
    if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "true" ]; then
      TLSINFO=$(eval echo "--tlsRootCertFiles \$PEER$1_ORG$2_CA")
      PEER_CONN_PARMS="$PEER_CONN_PARMS $TLSINFO"
    fi
    # shift by two to get the next pair of peer/org parameters
    shift
    shift
  done
  # remove leading space for output
  PEERS="$(echo -e "$PEERS" | sed -e 's/^[[:space:]]*//')"
}

# chaincodeInvoke <peer> <org> ...
# Accepts as many peer/org pairs as desired and requests endorsement from each
chaincodeInvoke() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["invoke","a","b","10"]}' >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode invoke -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["invoke","a","b","10"]}' >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Invoke execution on $PEERS failed "
  echo "===================== Invoke transaction successful on $PEERS on channel '$CHANNEL_NAME' ===================== "
  echo
}

createGame() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["createGame","game1","100","user1"]}' >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode invoke -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["createGame","game1","100","user1"]}' >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Invoke execution on $PEERS failed "
  echo "===================== Invoke transaction successful on $PEERS on channel '$CHANNEL_NAME' ===================== "
  echo
}

getActiveGames() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["getActiveGames"]}' >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode invoke -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["getActiveGames"]}' >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Invoke execution on $PEERS failed "
  echo "===================== Invoke transaction successful on $PEERS on channel '$CHANNEL_NAME' ===================== "
  echo
}

getCompletedGames() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["getCompletedGames"]}' >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode invoke -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["getCompletedGames"]}' >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Invoke execution on $PEERS failed "
  echo "===================== Invoke transaction successful on $PEERS on channel '$CHANNEL_NAME' ===================== "
  echo
}

joinGame() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["joinGame","game1","user2"]}' >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode invoke -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["joinGame","game1","user2"]}' >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Invoke execution on $PEERS failed "
  echo "===================== Invoke transaction successful on $PEERS on channel '$CHANNEL_NAME' ===================== "
  echo
}

openMoves() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["openMoves","game1"]}' >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode invoke -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["openMoves","game1"]}' >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Invoke execution on $PEERS failed "
  echo "===================== Invoke transaction successful on $PEERS on channel '$CHANNEL_NAME' ===================== "
  echo
}

endGame() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
    set -x
    peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["endGame","game1"]}' >&log.txt
    res=$?
    set +x
  else
    set -x
    peer chaincode invoke -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n $CC_NAME $PEER_CONN_PARMS -c '{"Args":["endGame","game1"]}' >&log.txt
    res=$?
    set +x
  fi
  cat log.txt
  verifyResult $res "Invoke execution on $PEERS failed "
  echo "===================== Invoke transaction successful on $PEERS on channel '$CHANNEL_NAME' ===================== "
  echo
}
```
