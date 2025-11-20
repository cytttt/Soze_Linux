#!/bin/bash
# Start running tofino-model program

function print_help() {
  echo "USAGE: $(basename ""$0"") -p <p4_program_name> [OPTIONS -- TOFINO_MODEL_OPTIONS]"
  echo "Options for running tofino-model:"
  echo "  -d NUM"
  echo "    Instantiate NUM devices in tofino-model"
  echo "  -h"
  echo "    Print this message"
  echo "  -g"
  echo "    Run with gdb"
  echo "  -f PORTINFO_FILE"
  echo "    Read port to veth mapping information from PORTINFO_FILE"
  echo "  -m"
  echo "    Run with port-monitor"
  echo "  -c TARGET_CONFIG_FILE"
  echo "    TARGET_CONFIG_FILE that describes P4 artifacts of the device"
  echo "  --conf-disable"
  echo "    Set model to not use p4 target config file"
  echo "  --int-port-loop <pipe-bitmap>"
  echo "    Put ports in internal loopback mode for specified pipes (0xf for all pipes)"
  echo "  --log-dir"
  echo "    Specify log file directory"
  echo "  --json-logs-enable"
  echo "    Enable the JSON event log stream"
  echo "  --pkt-log-len"
  echo "    Specify packet log length in bytes"
  echo "  --use-pcie-veth"
  echo "    Set model to use veth for pcie packets"
  echo "  --dod-test-mode"
  echo "    Set model to send every 10th DeflectOnDrop packet to Port0"
  echo "  --arch <Tofino|Tofino2>"
  echo "    Specifiy the chip architecture, defaults to Tofino"
  exit 0
}

trap 'exit' ERR

[ -z ${SDE} ] && echo "Environment variable SDE not set" && exit 1
[ -z ${SDE_INSTALL} ] && echo "Environment variable SDE_INSTALL not set" && exit 1

echo "Using SDE ${SDE}"
echo "Using SDE_INSTALL ${SDE_INSTALL}"

opts=`getopt -o d:c:f:p:ghm --long conf-disable,int-port-loop:,log-dir:,json-logs-enable,pkt-log-len:,use-pcie-veth,dod-test-mode,arch: -- "$@"`
if [ $? != 0 ]; then
  exit 1
fi
eval set -- "$opts"

# default P4_NAME to basic_ipv4
P4_NAME=""
# default num_devices to 1
NUM_DEVICES=1
# json file specifying of-port info
PORTINFO=None
# debug options
DBG=""
# internal port loop
INT_PORT_LOOP=""
LOG_DIR=""
JSON_LOGS_ENABLE=""
PKT_LOG_LEN=""
USE_PCIE_VETH=""
DOD_TEST_MODE=""
CONF_DISABLE=""
TARGET_CONFIG_FILE=""
CHIP_ARCH="Tofino"

HELP=false
PORTMONITOR=""
while true; do
    case "$1" in
      -d) NUM_DEVICES=$2; shift 2;;
      -f) PORTINFO=$2; shift 2;;
      -h) HELP=true; shift 1;;
      -g) DBG="gdb -ex run --args"; shift 1;;
      -m) PORTMONITOR="--port-monitor"; shift 1;;
      -p) P4_NAME=$2; shift 2;;
      -c) TARGET_CONFIG_FILE=$2; shift 2;;
      --conf-disable) CONF_DISABLE="$1"; shift 1;;
      --int-port-loop) INT_PORT_LOOP="--int-port-loop $2"; shift 2;;
      --log-dir) LOG_DIR="--log-dir $2"; shift 2;;
      --json-logs-enable) JSON_LOGS_ENABLE="--json-logs-enable"; shift 1;;
      --pkt-log-len) PKT_LOG_LEN="--pkt-log-len $2"; shift 2;;
      --use-pcie-veth) USE_PCIE_VETH="--use-pcie-veth $1"; shift 1;;
      --dod-test-mode) DOD_TEST_MODE="$1"; shift 1;;
      --arch) CHIP_ARCH=$2; shift 2;;
      --) shift; break;;
    esac
done

if [ $HELP = true ] || [ -z $P4_NAME ]; then
  print_help
fi

CHIP_ARCH=`echo $CHIP_ARCH | tr '[:upper:]' '[:lower:]'`
case "$CHIP_ARCH" in
  tofino2) CHIPTYPE=4;;
  tofino) CHIPTYPE=2;;
  *) echo "Invalid arch option specified ${CHIP_ARCH}"; exit 1;;
esac

P4TARGETCONFIG=""
if [[ $CONF_DISABLE == "" ]]; then
    if [[ $TARGET_CONFIG_FILE == "" ]]; then
      TARGET_CONFIG_FILE=$SDE_INSTALL/share/p4/targets/${CHIP_ARCH}/${P4_NAME}.conf
    fi
    [ ! -r $TARGET_CONFIG_FILE ] && echo "Target config file not found" && exit 1
    P4TARGETCONFIG+="--p4-target-config $TARGET_CONFIG_FILE "
fi

export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/lib:$SDE_INSTALL/lib:$LD_LIBRARY_PATH

echo "Using PATH ${PATH}"
echo "Using LD_LIBRARY_PATH ${LD_LIBRARY_PATH}"

#Start tofino-model
sudo env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" $DBG tofino-model \
	-d $NUM_DEVICES \
	$P4TARGETCONFIG --install-dir $SDE_INSTALL \
	--chip-type $CHIPTYPE \
	-f $PORTINFO $PORTMONITOR $LOG_DIR $JSON_LOGS_ENABLE $PKT_LOG_LEN $INT_PORT_LOOP $USE_PCIE_VETH $DOD_TEST_MODE $@
