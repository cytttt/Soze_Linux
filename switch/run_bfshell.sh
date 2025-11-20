#!/bin/bash
# Start running bfshell

function print_help() {
  echo "USAGE: $(basename ""$0"") [OPTIONS]"
  echo "Options for running bfshell:"
  echo "  -f <command_file>"
  echo "    bfshell command input file."
  echo "  -a <ipv4_addr>"
  echo "    Connect to this ipv4 address."
  echo "  -p <port>"
  echo "    open connection on this port."
  echo "  -d <devices>"
  echo "    Wait for these devices to be ready (1 or 0-2 or 0,4,6-8)"
  echo "  --no-status-srv"
  echo "    Do not query bf_switchd's status server"
  echo "  --status-port <port number>"
  echo "    Specify bf_switchd's status server port number; the default is 7777"
  echo "  -h"
  echo "    Display this help."
  exit 0
}

trap 'exit' ERR

[ -z ${SDE} ] && echo "Environment variable SDE not set" && exit 1
[ -z ${SDE_INSTALL} ] && echo "Environment variable SDE_INSTALL not set" && exit 1

echo "Using SDE ${SDE}"
echo "Using SDE_INSTALL ${SDE_INSTALL}"

opts=`getopt -o f:a:p:d:h --long no-status-srv --long status-port: -- "$@"`
if [ $? != 0 ]; then
  exit 1
fi
eval set -- "$opts"

SKIP_STATUS_SRV=false
HELP=false

while true; do
    case "$1" in
      -f) FILE_NAME=$2; shift 2;;
      -a) IPV4=$2; shift 2;;
      -p) PORT=$2; shift 2;;
      -d) DEVICES=$2; shift 2;;
      -h) HELP=true; shift 1;;
      --status-port) STS_PORT=$2; shift 2;;
      --no-status-srv) SKIP_STATUS_SRV=true; shift 1;;
      --) shift; break;;
    esac
done

if [ $HELP = true ]; then
  print_help
fi

# Check in with bf_switchd's status server to make sure it is ready
STS_PORT_STR="--port 7777"
if [ "$STS_PORT" != "" ]; then
  STS_PORT_STR="--port $STS_PORT"
fi
STS_HOST_STR="--host localhost"
if [ "$IPV4" != "" ]; then
  STS_HOST_STR="--host $IPV4"
fi
STS_DEV_STR="--device 0"
if [ "$DEVICE" != "" ]; then
  STS_DEV_STR="--device $DEVICES"
fi
if [ "$TARGET" != "bmv2" ]; then
  if [ $SKIP_STATUS_SRV = false ]; then
    python $SDE_INSTALL/lib/python2.7/site-packages/p4testutils/bf_switchd_dev_status.py \
      $STS_HOST_STR $STS_PORT_STR $STS_DEV_STR
  fi
fi

FILE_NAME_STR=""
if [ "$FILE_NAME" != "" ]; then
  FILE_NAME_STR="-f $FILE_NAME"
fi
IPV4_STR=""
if [ "$IPV4" != "" ]; then
  IPV4_STR="-a $IPV4"
fi
PORT_STR=""
if [ "$PORT" != "" ]; then
  PORT_STR="-p $PORT"
fi

#Run bfshell client
echo $SDE_INSTALL/bin/bfshell $FILE_NAME $IPV4 $PORT
$SDE_INSTALL/bin/bfshell $FILE_NAME_STR $IPV4_STR $PORT_STR
