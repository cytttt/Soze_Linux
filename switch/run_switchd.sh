#!/bin/bash
# Start running switchd application program

function print_help() {
  echo "USAGE: $(basename ""$0"") {-p <...> | -c <...>} [OPTIONS -- SWITCHD_OPTIONS]"
  echo "Options for running switchd:"
  echo "  -p <p4_program_name>"
  echo "    Load driver with artifacts associated with P4 program"
  echo "  -c TARGET_CONFIG_FILE"
  echo "    TARGET_CONFIG_FILE that describes P4 artifacts of the device"
  echo "  --skip-p4"
  echo "    Skip loading of P4 program in device"
  echo "  --skip-hld <skip_hld_mgr_list>"
  echo "    Skip high level drivers:"
  echo "    p:pipe_mgr, m:mc_mgr, k:pkt_mgr, r:port_mgr, t:traffic_mgr"
  echo "  --skip-port-add"
  echo "  --kernel-pkt"
  echo "    Skip adding ports"
  echo "  -h"
  echo "    Print this message"
  echo "  -g"
  echo "    Run with gdb"
  echo "  --no-status-srv"
  echo "    Do not start bf_switchd's status server"
  echo "  --status-port <port number>"
  echo "    Specify the port that bf_switchd's status server will use; the default is 7777"
  echo "  --arch <Tofino|Tofino2>"
  echo "    Specifiy the chip architecture, defaults to Tofino"
  exit 0
}

trap 'exit' ERR

[ -z ${SDE} ] && echo "Environment variable SDE not set" && exit 1
[ -z ${SDE_INSTALL} ] && echo "Environment variable SDE_INSTALL not set" && exit 1

echo "Using SDE ${SDE}"
echo "Using SDE_INSTALL ${SDE_INSTALL}"

opts=`getopt -o c:p:ghsl:a --long skip-p4,skip-port-add,kernel-pkt,skip-hld:,status-port:,no-status-srv,arch: -- "$@"`
if [ $? != 0 ]; then
  exit 1
fi
eval set -- "$opts"

# P4 program name
P4_NAME=""
# debug options
DBG=""
# target config file
TARGET_CONFIG_FILE=""

HELP=false
SKIP_P4=false
SKIP_HLD=""
SKIP_PORT_ADD=false
KERNEL_PKT=false
SKIP_STATUS_SRV=false
CHIP_ARCH="Tofino"
while true; do
    case "$1" in
      -h) HELP=true; shift 1;;
      -g) DBG="gdb -ex run --args"; shift 1;;
      -p) P4_NAME=$2; shift 2;;
      -c) TARGET_CONFIG_FILE=$2; shift 2;;
      --skip-p4) SKIP_P4=true; shift 1;;
      --skip-hld) SKIP_HLD=$2; shift 2;;
      --skip-port-add) SKIP_PORT_ADD=true; shift 1;;
      --kernel-pkt) KERNEL_PKT=true; shift 1;;
      --status-port) STS_PORT=$2; shift 2;;
      --no-status-srv) SKIP_STATUS_SRV=true; shift 1;;
      --arch) CHIP_ARCH=$2; shift 2;;
      --) shift; break;;
    esac
done

if [ $HELP = true ] || ( [ -z $P4_NAME ] && [ -z $TARGET_CONFIG_FILE ] ); then
  print_help
fi

CHIP_ARCH=`echo $CHIP_ARCH | tr '[:upper:]' '[:lower:]'`
case "$CHIP_ARCH" in
  tofino2) ;;
  tofino) ;;
  *) echo "Invalid arch option specified ${CHIP_ARCH}"; exit 1;;
esac

SKIP_P4_STR=""
if [ $SKIP_P4 = true ]; then
  SKIP_P4_STR="--skip-p4"
fi
SKIP_HLD_STR=""
if [ "$SKIP_HLD" != "" ]; then
  SKIP_HLD_STR="--skip-hld $SKIP_HLD"
fi
SKIP_PORT_ADD_STR=""
if [ $SKIP_PORT_ADD = true ]; then
  SKIP_PORT_ADD_STR="--skip-port-add"
fi

STS_PORT_STR="--status-port 7777"
if [ "$STS_PORT" != "" ]; then
  STS_PORT_STR="--status-port $STS_PORT"
fi
KERNEL_PKT_STR=""
if [ $KERNEL_PKT = true ]; then
  KERNEL_PKT_STR="--kernel-pkt"
fi

if [ $SKIP_STATUS_SRV = true ]; then
  STS_PORT_STR=""
fi

if [ -z ${TARGET_CONFIG_FILE} ]; then
  TARGET_CONFIG_FILE=$SDE_INSTALL/share/p4/targets/$CHIP_ARCH/$P4_NAME.conf
fi

[ ! -r $TARGET_CONFIG_FILE ] && echo "File $TARGET_CONFIG_FILE not found" && exit 1

echo "Using TARGET_CONFIG_FILE ${TARGET_CONFIG_FILE}"

export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib:$LD_LIBRARY_PATH

echo "Using PATH ${PATH}"
echo "Using LD_LIBRARY_PATH ${LD_LIBRARY_PATH}"

#Start tofino-driver
sudo env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $DBG bf_switchd\
	--install-dir $SDE_INSTALL --conf-file $TARGET_CONFIG_FILE \
	$SKIP_HLD_STR $SKIP_P4_STR $SKIP_PORT_ADD_STR $STS_PORT_STR $KERNEL_PKT_STR $@

