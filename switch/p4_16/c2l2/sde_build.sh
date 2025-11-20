#!/bin/bash

#
# sde_build
#
# Barefoot Networks Software Development Environment (bf-sde) is a 
# software distribution, consisting of multiple independent packages. 
#
# While building each package is a fairly trivial procedure (majority of them
# follow the standard GNU "configure;make;make install" sequence) the sheer
# number of packages calls for some automation. In addition to that, there are
# certain pre-requisites to be installed. 
# 
# Also, some packages require certain configuration parameters and some of those
# need to be specified consistently throughout the whole build (e.g. --prefix)
#
# This script serves as an example how the full build can be performed. It
# doesn't claim to support all the options and their combinations, but provides
# a good start. In addition, it is using VPATH builds to simplify source
# directory management. 
#

#
# Just stop if there is any problem
#
set -e

#
# Simple debugging
#
#set -x

#
SCRIPT_VERSION="8.4.0"

#
# Run-time parameters (normally configurable via command-line options)
#
build_arch=x86_64
host_arch=x86_64
target_arch=x86_64

jobs=0                    # Number of jobs for parallel builds; 0 means let the
                          # script determine the best number

first_step=0              # First build step. Use -n to see the list
last_step=1000            # Last  build step
list_steps=0
force_autogen=0           # Force ./configure regeneration
force_cleanup=0           # Do cleanup of $SDE_INSTALL, $SDE_BUILD and $SDE_LOGS
thrift=yes                # By default, compile Thrift for the APIs
grpc=yes                  # By default, compile gRPC support 
install_deps=1            # By default, install dependencies

real_hardware=0           # By default, compile the drivers for the model env.

install_bf_platforms=1    # By default, install bf-platforms, but for the real
                          # hardware only

do_dma_setup=1            # By default, execute dma_setup.sh if DMA has not yet
                          # been set up

sanity_deps_check=1       # By default perform sanity dependency checks

switch_pkg="switch"       # By default we use switch and not switch-p4-16
switch_compiler=""        # Usually determined automatically. For switch
                          # you can choose between p4c-tofino and p4c(bf-p4c)

switch_extra_platforms=""
examples_extra_platforms=""
with_examples=1           # Build examples
with_alpha=0              # Build alpha components
with_p4i=1                # Install p4i
quick=0                   # Do a quick build (no switch, no examples)
yes=0
check_version=1           # Check script version vs. SDE version

default_p4flags="--verbose 2 -g --create-dot"
default_p4c_flags="--verbose 2 -g --create-graphs"

#
# Useful constants and shortcuts. You can change those, but there is probably
# no need.
# 
packages=packages         # The SDE subdirectory SDE where package tarballs are
pkgsrc=pkgsrc             # The SDE subdirectory, where tarbals are untarred
build=build               # The SDE subdirectory, where the builds are done
logs=logs/sde-build       # The SDE subdirectory, where build logs are stored

sde_min_gb=4              # We recommend at least 4GB RAM for SDE build
log_lines=15              # How many lines from a logfile to show on error

#
# Help 
#
function print_help() {
    echo "USAGE: $(basename ""$0"") [OPTIONS]"
    cat <<EOF | less

This is a simple script that builds the whole SDE, according
to the official README files (more or less) :)

Options:
    -h        Print this help
    -v        Print version information
    -r        Build on the real system (as opposed to models)
    -n        Dry run. Display all the steps, but do not execute
    -a        Force autoconf rerun
    -c        Force cleanup of install, build and log directories

    -s N      Start with step number N
    -e N      End with step number N
    -S <name> Execute step(s) that match <name>

    -t yes/no Enable/Disable Thrift Support for APIs (Enabled)
    -g yes/no Enable/Disable gRPC Support for BF-RT APIs (Enabled)

    -j N      When building code, execute up to N jobs in parallel

    -q
    --quick   Do a quick build: No dependencies, no switch, no examples

    --no-deps 
              Do not install dependencies. This is useful if you have
              done it before or if there is no internet connection
    --do-not-check-deps
              Disable sanity dependency checks
    --do-not-check-version
              Disable SDE version checking (allows a mismatch between
              the script version and SDE version)
    --no-bmv2 
              Do not install BMv2-related toolchain and do not build
              for BMv2 platforms (This is the default)
    --with-bmv2 (Deprecated)
              Starting with SDE-8.3.0 BMv2 is no longer shipped with SDE
    --no-bf-platforms
              Do not print the warning message about the need to build BSP
              separately
    --no-dma-setup 
              Do not setup DMA pool by running dma_setup.sh script.
              The script performs necessary checks to detect if that
              has been previously done. Usually, you would use this 
              parameter is you use your own DMA allocation scheme
    --switch-pkg <none, p4_16, p4_14>
              Choose the package for the reference data plane program.
               * Default is p4_14 (p4-14 and 14 are also acceptable). This 
                 chooses "switch" package
               * p4_16 (p4-16, 16) chooses switch-p4-16 instead
               * none (no) tells the script to not build any
    --switch-compiler <p4c-tofino|bf-p4c|p4c>
              Build switch.p4 (not switch-p4-16) using the specified compiler.
              By default, the compiler (p4c-tofino or bf-p4c) is chosen
              automatically. p4c and bf-pc are equivalent. 
              Note, that his parameter does not allow specifying a pathname
              to an arbitrary compiler -- it's a compiler type, really.
    --switch-profile <switch.p4 profile name>
              Build a different profile of switch.p4. Default is
              DC_BASIC_PROFILE
    --switch-extra-flags=<additional flags to build switch>
              Provide additional flags to build switch package with. 
              Typical usage: 
                 --switch-extra-flags="P4FLAGS=--force-match-dependency"
    --switch-extra-platforms=
              Additional platforms (besides --with-tofino) to use for
              building the switch package. Currently there are none.
    --with-examples
              Build p4-examples. Both P4_14 and P4_16 examples are now
              built by default, unless -q is specified
    --no-examples
              Do not build p4-examples
    --examples-extra-platforms=
              Additional platforms (besides --with-tofino) to use for
              building the p4-examples package. Currently, there are none.
    --bf-drivers-extra-flags=<additional flags to build bf-drivers>
              Provide additional flags to build bf-drivers with.
              Typical usage:
                 --bf-drivers-extra-flags="--without-kdrv"
    --yes
              Proceed, without asking questions. Please, be careful,
              since this can lead to file deletion, long rebuild times, etc.

Notes:
    1. Unless \$SDE is set, the build is done in \$CWD
    2. All tarballs are un-tarred into \$SDE/$pkgsrc
    3. All packages are built in \$SDE/$build using VPATH
    4. All logs are placed in \$SDE/$logs as <step#>-<step-name>.log

EOF
}

print_help_dependencies() {
    cat <<EOF

=====================================================================
One of depency installation scripts failed.

Your environment was detected as:

DISTRIB_ID:          "$DISTRIB_ID"
DISTRIB_RELEASE:     "$DISTRIB_RELEASE"
DISTRIB_CODENAME:    "$DISTRIB_CODENAME"
DISTRIB_DESCRIPTION: "$DISTRIB_DESCRIPTION"

There are two main reasons for this failure:
   1. You are trying to execute dependency installation script on an 
      unsupported system. Please, see SDE Release Notes for the list 
      of the systems that are supported. You have a choice of modifying
      the dependency installation scripts for your systems or installing
      dependencies manually and then running this script with --no-deps flag
   
   2. You do not have Internet connectivity, which is required to download 
      the dependencies. Please, check your Internet connectivity

If your system is not connected to the Internet, you can run this
script with --no-deps flag

If your system is connected to the Internet via a proxy, try to set
\$http_proxy and \$https_proxy environment variables, e.g

       export https_proxy=proxy.mycompany.com
       export http_proxy=proxy.mycompany.com

There can be other reasons for the dependencies to fail as well.
Typically they can be traced to the differences in the environment.
=====================================================================

EOF
}

print_help_non_standard_distribution() {
                cat <<EOF

ERROR: The current dependency installation scripts included in the SDE
       support only Fedora and Ubuntu distributions. 

       We could not detect either of these systems, but found this:
       
DISTRIB_ID:          "$DISTRIB_ID"
DISTRIB_RELEASE:     "$DISTRIB_RELEASE"
DISTRIB_CODENAME:    "$DISTRIB_CODENAME"
DISTRIB_DESCRIPTION: "$DISTRIB_DESCRIPTION"

       If you are running the script on Wedge-100b system under ONL, 
       you need to download the required dependencies tarball from the
       Barefoot support portal, untar it and install the dependencies accoring 
       to the instructions in the README file, included in the tarball. 

       After installing dependencies on Wedge-100b, you should run this 
       script using the following (or similar command):

       $0 -r --no-deps

       On other systems you need to consult the system vendor or adapt SDE
       dependency installation scripts accordingly.
        
       If you believe you got this message erroneously, you can run the script
       with --do-not-check-deps parameter, but you have been warned.

EOF
}

print_help_arch() {
    cat <<EOF

ERROR: This script builds SDE for $build_arch architecture by default.
       You are attempting to build for `uname -m` architecture instead.
       If that's your intention, please, edit the script and change the
       values of the variables build_arch, host_arch and target_arch to
       `uname -m`.

IMPORTANT NOTES:
    1. This script has been verified on x86_64 architecture only
    2. Cross-compilation is currently not supported

EOF
}

print_help_install_binaries() {
    cat <<EOF

ERROR: It looks like you have already installed the binary programs. 
       If you wish to re-install them, please run this script with the '-c'
       option to clear everything first.

EOF
}

print_version() {
    echo "Developed for SDE-$SCRIPT_VERSION"
}

print_help_version() {
    cat<<EOF

ERROR: This version of the script was developed for a different SDE release.
       
       sde_build.sh: $SCRIPT_VERSION
                SDE: $SDE_VERSION

       If you know what you are doing and would like to disable this check,
       rerun this script with --do-no-check-version flag. However, you have
       been warned.
    
EOF
}

print_help_bmv2() {
    cat <<EOF
ERROR: Starting with SDE-8.3.0, BMv2 (both in SimpleSwitch and Tofino
       architectures) is no longer supported. All BMv2-related  packages
       have been removed from the SDE.

       BMv2-SimpleSwitch is still available from P4.Org. All the support 
       for it will also come from the P4 community.

       BMv2-Tofino is no longer developed or supported by Barefoot.
       Please use the register-accurate tofino-model instead. 
EOF
}

print_help_switch_pkg() {
    cat <<EOF
ERROR: The value for switch-pkg parameter <$1> is not recognized.
       Acceptable values are:
        * switch/p4-14/p4_14/14 for the "switch" package
        * switch-p4-16/p4_16/16 for the "switch-p4-16" package
        * none/no directs the script to not build switch at all
EOF
}

print_help_switch_p4_16() {
    cat <<EOF

WARNING: You chose to install switch-p4-16 package. 
         Please note that due to a known issue (SWI-1724), switchd will not
         be able to run any other P4 program as long as switch-p4-16 is 
         installed.

         To uninstall switch-p4-16 use the following commands:

              cd \$SDE/build/switch-p4-16; make uninstall

         To install switch-p4-16 back use the following commands:

              cd \$SDE/build/switch-p4-16; make -j $jobs install

EOF
}

print_help_compiler() {
    cat <<EOF
ERROR: Unrecognized compiler <$1>. Acceptable names are:
        * p4c-tofino -- for the older (p4-hlir-style) compiler 
        * p4c/bf-p4c -- for the newer p4_14/p4_16 compiler
      Note, that the parameter doesn't allow you to specify the path
      to an arbitrary executable. It's really  compiler type.
EOF
}

print_help_bf_platforms() {
    cat <<EOF
====================
ATTENTION: You chose to build the SDE for the real hardware and this requires
           platform-specific support package (a.k.a. BSP). 

           Starting with SDE-8.0.0 Wedge-100B BSP (bf-platforms) package is no 
           longer a part of the SDE. You need to obtain an appropriate BSP for
           your board and then build and install it according to the vendor's
           instructions. Until you do that, you can exercise SDE on the
           tofino-model. 

           For example, you can find BSP for Wedge-100B systems on Barefoot
           support portal.
====================
EOF
}

#
# Function: section <name>
#
# Print a name of the section when listing the steps
#
section() {
    if [ $list_steps -ne 0 ]; then
        echo 
        echo "$@"
        echo
    fi
}
    
#
# Function: step <command>
#
# Execute the step (unless told to skip it)
#
step() {
    if [ $first_step -le $step -a $step -le $last_step ]; then
        case "$@" in
            *${step_name}*)
                if [ $list_steps -ne 0 ]; then
                    echo "Step $step:" "$@"
                else 
                    "$@"
                fi
        esac
    fi
    step=$[$step+1]
}

#
# Function: package_dir <package_name>
#
# This function chooses the proper package in $SDE_PKGSRC and returns the base
# directory name (i.e. without $SDE_PKGSRC prefix). If there is no such package, 
# an empty string is returned and then the upper layer code can decide how to 
# proceed. If there are multiple versions of the 
# same package, then the function allows the user to choose interactively
#
package_dir() {
    local package_name=$1; shift
    local p
    
    if [ ! -d $SDE_PKGSRC ]; then
        return 0;
    fi

    local package_list=( \
        `cd $SDE_PKGSRC; \
         ls -d ${package_name} ${package_name}-[0-9]* 2>/dev/null`)
    
    local num_packages=${#package_list[@]}
    local prompt
    case $num_packages in
        0)
            echo ""
            ;;
        1)
            echo ${package_list[0]}
            ;;
        *)
            prompt="\nWARNING: Multiple versions of $package_name"
            prompt="$prompt package found in \$SDE/pkgsrc"
            for p in `seq 0 $[$num_packages-1]`; do
                prompt="${prompt}\n    ${p} -- ${package_list[$p]}"
            done
            prompt="$prompt\nPlease choose one(0..$[$num_packages-1])[0]"

            if [ $yes -ne 1 ]; then
                prompt=`echo -e $prompt`
                read -p "$prompt " p
                if [ -z $p ]; then
                    p=0
                fi
            else
                p=0
            fi                
            echo ${package_list[$p]}
            ;;
    esac
    return 0
}

#
# Function: version_compare ver1 ver2
#
# Borrowed from https://stackoverflow.com/questions/4023830
#
# Returns (echoes):
#    "=": ver1 == ver2
#    ">": ver1 >  ver2
#    "<": ver2 <  ver2
version_compare () {
    if [ $# -ne 2 ]; then
        return 1
    fi
    
    if [[ $1 == $2 ]]
    then
        echo "="
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            echo ">"
            return 0
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            echo "<"
            return 0
        fi
    done
    echo "="
    return 0
}

#
# Autodetecting the number of the CPUs
#
get_ncpus() {
    nproc

    # If that utility is not present (it should be), you can use the following
    # code instead
    #    ncpu=`grep ^processor /proc/cpuinfo | tail -1 | sed -e 's/^.*: //'`
    #    echo $[ncpu+1]
}

#
# Function get_onl_manifest_item
#
get_onl_manifest_item() {
    grep \"$1\" /etc/onl/rootfs/manifest.json | cut -d: -f2 | sed -e 's/ *\(".*"\).*/\1/'
    return 0
}

# 
#
# Function get_os_info
#
# The function sets the following variables, according to the OS:
# UNAME_A, DISTRIB_ID, DISTRIB_RELEASE, DISTRIB_CODENAME, DISTRIB_DESCRIPTION
# Normally, it gets them from /etc/lsb-release and trie to guess in other cases
#
get_os_info() {
    UNAME_A=`uname -a`
    if [ -r /etc/lsb-release ]; then
        . /etc/lsb-release
    elif [ -r /etc/onl/rootfs/manifest.json ]; then
        # This is an ONL system, so we can use manifest.json
        DISTRIB_ID="ONL"
        DISTRIB_RELEASE=`get_onl_manifest_item PRODUCT_ID_VERSION`
        DISTRIB_CODENAME=`get_onl_manifest_item PRODUCT_VERSION`
        DISTRIB_DESCRIPTION=`get_onl_manifest_item VERSION_STRING`
    else         
        # Here are some heuristics for non-LSB systems.
        DISTRIB_ID="Unknown"
        DISTRIB_RELEASE="Unknown"
        DISTRIB_CODENAME="Unknown"
        DISTRIB_DESCRIPTION="Unknown, non-LSB System"
    fi
}

#
# Function: check_environment
#
# Ensure that $SDE and $SDE_INSTALL are properly set and generally
# things make sense. Use reasonable defaults
#
check_environment() {
    if [ -z $SDE ]; then
        echo "WARNING: SDE Environment variable is not set"
        echo "         Assuming $PWD"
        export SDE=$PWD
    else 
        echo "Using SDE ${SDE}"
    fi

    #
    # Basic Checks that SDE is valid
    #
    if [ ! -d $SDE ]; then
        echo "  ERROR: \$SDE ($SDE) is not a directory"
        exit 1
    fi

    cd $SDE
    if [ $? != 0 ]; then
        echo "  ERROR: Cannot change directory to \$SDE"
        exit 1
    fi

    if [ -z $SDE_INSTALL ]; then
        echo "WARNING: SDE_INSTALL Environment variable is not set"
        echo "         Assuming $SDE/install"
        export SDE_INSTALL=$SDE/install
    else
        echo "Using SDE_INSTALL ${SDE_INSTALL}"
    fi
    
    if [[ ":$PATH:" == *":$SDE_INSTALL/bin:"* ]]; then
        echo "Your PATH contains \$SDE_INSTALL/bin. Good"
    else
        echo "Adding $SDE_INSTALL/bin to your PATH"
        PATH=$SDE_INSTALL/bin:$PATH
    fi

    #
    # Check SDE version
    #
    if SDE_MANIFEST=`ls $SDE/bf-sde-*.manifest 2> /dev/null`; then
        SDE_VERSION=`basename $SDE_MANIFEST .manifest | sed -e 's/bf-sde-\(.*\)/\1/'`
        echo "Found SDE-$SDE_VERSION in \$SDE"
    else
        echo "  ERROR: SDE manifest file not found in \$SDE"
        exit 1
    fi

    if [ $check_version -eq 1 ]; then
        if [ $SDE_VERSION != $SCRIPT_VERSION ]; then
            print_help_version
            exit 1
        fi
    fi
    
    SDE_PACKAGE_LIST=`tr -d ' ' < $SDE_MANIFEST`
    
    #
    # Check the current CPU Architecture
    #
    if [ $build_arch != `uname -m` ]; then
        print_help_arch
        exit 1;
    fi

    #
    # Check available RAM
    #
    total_mem=`grep MemTotal /proc/meminfo | sed -e 's/.* \([0-9]*\) .*/\1/'`
    total_mem_gb=$[total_mem/1000000]
    if [ $total_mem_gb -lt $sde_min_gb ]; then
        echo "ERROR: You system has only ${total_mem_gb}GB of RAM"
        echo "       To build SDE you will need at least ${sde_min_gb}GB"
        exit 1
    fi

    #
    # Basic System Info
    #
    get_os_info
    echo "OS Name: $DISTRIB_DESCRIPTION"
    
    ncpus=`get_ncpus`
    echo "This system has ${total_mem_gb}GB of RAM and ${ncpus} CPU(s)"

    #
    # For parallel builds we need to make sure each process gets at least
    # $sde_min_gb/2 GB of memory
    recommended_jobs=$ncpus
    if [ $[total_mem_gb*2/sde_min_gb] -le $ncpus ]; then
        recommended_jobs=$[total_mem_gb*2/sde_min_gb]
    fi

    # The number of jobs can be specified explicitly. In this case do not
    # override it
    if [ $jobs -eq 0 ]; then 
        jobs=$recommended_jobs
    fi

    echo "Parallelization:  Recommended: -j$recommended_jobs   Actual: -j$jobs"
    
    SDE_PACKAGES=$SDE/$packages
    SDE_PKGSRC=$SDE/$pkgsrc
    SDE_BUILD=$SDE/$build
    SDE_LOGS=$SDE/$logs

    return 0
}

#
# Function: start_log
#
# Put a standard header in every logfile
#
start_log() {
    local logfile=$1; shift

    cat <<EOF > $logfile
=========================================================================
         File: `basename $logfile`
      Created: `date`
 Command Line: $CMDLINE
          SDE: $SDE (`basename $SDE_MANIFEST .manifest`)
 Build System: `uname -a`
 Distribution: $DISTRIB_DESCRIPTION
   Build Arch: $build_arch
       CPU(s): $ncpus
          RAM: ${total_mem_gb}GB
       Job(s): -j$jobs
 sde_build.sh: `print_version`

  Disk Space: for \$SDE
`df -H $SDE`
=========================================================================
 Current Dir: `pwd`
   Executing: $*
=========================================================================
EOF
}

#
# Function: show_log
#
# Prominently display the last $log_lines from the relevant logfile on error
#
show_log() {
    echo "=========================" `basename $1` "========================="
    tail -$log_lines $1
    echo "=========================" `basename $1` "========================="
    echo
    echo "ERROR: For the details and to obtain technical support see the file"
    echo "       $1"
    echo
}

#
# Function: untar_packages
#
# This one is needed until we change the directory 
# structure of the distribution. Just untar .tgz aside into pkgsrc/

untar_packages() {
    local package
    local yes_no
    
    if [ -d $SDE_PKGSRC ]; then
        if [ $yes -ne 1 ]; then
            read -p "\$SDE/$pkgsrc directory already exists. Extract packages again [y/N]? " yes_no
        else
            yes_no="Y"
        fi
        
        case $yes_no in
            [Yy]*) ;;
            *) return 0
        esac
    fi
    
    echo "Clearing \$SDE/$pkgsrc"
    sudo rm -rf $SDE_PKGSRC

    mkdir -p $SDE_PKGSRC
    cd $SDE_PKGSRC

    for p in $SDE_PACKAGE_LIST; do
        package=`echo $p | cut -d: -f1`
        package_version=`echo $p | cut -d: -f2`
        pkg=${package}-${package_version}

        do_extract=1
        
        if [ $with_alpha -eq 0 ]; then
            case $package_version in
                *alpha*|*beta*) do_extract=0;;
                *) ;;
            esac
        fi
        
        if [ $do_extract -ne 0 ]; then 
            if [ ! -f $SDE_PACKAGES/${pkg}.tgz ]; then
                echo "ERROR: Cannot find package $pkg in $SDE_PACKAGES"
                return 1
            fi
            
            if [ -d $SDE/${pkg} ]; then 
                echo -n "Moving package $pkg into $pkgsrc/$package ... "
                mv $SDE/$pkg $SDE_PKGSRC/$package
                echo DONE
            else
                printf "Extracting package %-30s ... " $pkg 
                tar xzf $SDE_PACKAGES/${pkg}.tgz
                mv $pkg $package
                echo DONE
            fi
            echo ${package_version} > ${SDE_PKGSRC}/${package}/RELEASE
        fi
    done
    
    cd $SDE
}

#
# Function: cleanup_dirs <dir1> <dir2> ...
#
cleanup_dirs() {
    local dir

    if [ $list_steps -eq 0 ]; then 
        for dir in $*; do
            echo -n "Cleaning up $dir ... "
            sudo rm -rf $dir;
            echo DONE
        done
    fi
}

#
# Function: pkg_version_check pkg_name required_version
#
# The function checks if the package is installed and the version requirement
# is met
pkg_version_check() {
    local pkg=$1;         shift
    local req_version=$1; shift

    # echo -n "$pkg >= $req_version "
    if pkg-config --exists $pkg; then
        pkg_version=`pkg-config --modversion $pkg`
        # echo -n "$pkg_version "
        case `version_compare $pkg_version $req_version` in
            [\>=]) return 0 ;;
             [\<])
                 echo FAILED
                 cat <<EOF

ERROR: Found $pkg package version $pkg_version. However, SDE
       requires at least version $req_version

       Please, check your installation. Most probably you have an older
       version of this package lingering around. In that case you need to 
       remove it and re-install the dependencies.

EOF
                 return 1;;
                 
        esac 
    fi  
}
 
# Function check_deps
#
# This function will check that at least some well-known dependencies have been
# installed. It is used as a safety check when --no-deps is used. Note, that
# this is not a comprehensive check, but a basic "safety net". The real checking
# is the responsibility of the ./configure scripts

check_deps() {
    ret=0
    
    echo -n "Checking that required dependencies are present   ... "
    if [ -z `which git` ]; then
        echo "ERROR: git is not found in your PATH"
        ret=1
    fi
    
    if [ -z `which easy_install` ]; then
        echo FAILED
        echo "ERROR: python-setuptools are not installed"
        ret=1
    fi
    
    if [ -z `which scapy` ]; then
        echo FAILED
        echo "ERROR: scapy is not found in your PATH"
        ret=1
    fi
    
    if [ ! -d /usr/include/libnl3 -a ! -d /usr/local/include/libnl3 ]; then
        echo FAILED
        echo "ERROR: libnl3-dev is not installed"
        ret=1
    fi
    
    if [ $thrift = "yes" ]; then
        if [ -z `which thrift` ]; then
            echo FAILED
            echo "ERROR: Thrift compiler is not found in your path"
            ret=1
        fi
    fi
    
    if [ $grpc = "yes" ]; then
        if [ -z `which pkg-config` ] ;then
            echo FAILED
            echo "ERROR: pkg-config is not found in your path"
            ret=1
        else
            if ! pkg_version_check grpc 3.0.0; then
                ret=1
            fi
            
            if ! pkg_version_check grpc++ 1.3.0; then
                ret=1
            fi
            
            if ! pkg_version_check protobuf 3.0.0; then
                ret=1
            fi
        fi
        
        if [ -z `which protoc` ]; then
            echo FAILED
            echo "ERROR: Protobuf compiler is not found in your path"
            ret=1
        fi
        if [ -z `which grpc_cpp_plugin` ]; then
            echo FAILED
            echo "ERROR: GRPC C++ plugin is not found in your path"
            ret=1
        fi
    fi

    if [ $ret -eq 1 ]; then
        cat <<EOF

ERROR: At least some of the required dependencies do not appear to be 
       present in your system.

       If you chose to run the script with --no-deps parameter, then you
       need to ensure that the correct dependencies are present by installing
       them manually.

       If you are running the script on Wedge-100b system under ONL, 
       you need to download the required dependencies tarball from the
       Barefoot support portal, untar it and install the dependencies accoring 
       to the instructions in the README file, included in the tarball. 

       On other systems you need to consult the system vendor or adapt SDE
       dependency installation scripts accordingly.

       If you believe that the dependencies were installed automatically by
       this script (you ran it without --no-deps), it might indicate a problem
       with the standard SDE dependency installation scripts. Most probably some
       of the installed dependencies conflict with the other versions that might
       be present in your system. If you can't rectify the problem by removing 
       the conflicting packages, please file a support ticket.
 
       If you believe you got this message erroneously, you can run the script
       with --do-not-check-deps parameter, but you have been warned.

EOF
    else
        echo DONE
    fi
    
    return $ret
}

#
# Function: install_deps <description> <file-to-run.sh>
#
# Install global dependencies (scripts are in $SDE)
#
install_deps() {
    local result
    local desc="$1";   shift
    local script="$1"; shift
    local cmd
    
    if [ $sanity_deps_check -ne 0 ]; then
        if [[ ! $DISTRIB_ID =~ "Fedora" ]]; then
            if [[ ! $DISTRIB_ID =~ "Ubuntu" ]]; then
                print_help_non_standard_distribution
                exit 1
            fi
        fi
    fi
    
    printf "Installing Dependencies for %-35s ... " "$desc ($script)"
    cd $SDE
    cmd="$SDE/$script $@"
    start_log $SDE_LOGS/${step}-${script}.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${script}.log; then 
        echo DONE
        result=0
    else 
        echo FAILED
        print_help_dependencies
        show_log $SDE_LOGS/${step}-${script}.log
        result=1
    fi

    cd $SDE
    return $result
}

install_pkg_deps() {
    local result
    local desc="$1";       shift
    local pkg_name="$1";   shift
    local script="$1";     shift
    local cmd
    
    pkg_dir=`package_dir $pkg_name`
    if [ ! -z $pkg_dir ]; then
        if [ -x $SDE_PKGSRC/$pkg_dir/$script ]; then  
            printf "Installing Dependencies for %-35s ... " "$desc ($script)"
            cd $SDE_PKGSRC/$pkg_dir

            cmd="./$script $@"
            start_log $SDE_LOGS/${step}-${script}.log $cmd
            if $cmd &>> $SDE_LOGS/${step}-${script}.log; then 
                echo DONE
                result=0
            else 
                echo FAILED
                show_log $SDE_LOGS/${step}-${script}.log
                result=1
            fi

            cd $SDE
            return $result
        else
            echo "WARNING: Cannot find dependency installation script $script" 
            echo "         in package directory \$SDE/$pkgsrc/$pkg_dir"
            echo "         This may happen if sde_build.sh script is too old"
            echo "         or too new for a given SDE version."
        fi
    else
        echo "WARNING: Cannot find package $pkg_name in \$SDE/$pkgsrc"        
    fi

    # If we got here, that means that nothing was done, either because
    # the package is not present or there was nothing to install
    echo "WARNING: Skipping the step <install_pkg_deps $pkg_name>."
    echo "         Note: This may cause problems later..."
    return 0
}

install_pkg_deps_pip() {
    local result
    local desc="$1";       shift
    local pkg_name="$1";   shift
    local script="$1";     shift

    pkg_dir=`package_dir $pkg_name`
    if [ ! -z $pkg_dir ]; then
        if [ -r $SDE_PKGSRC/$pkg_dir/$script ]; then  
            printf "Installing Dependencies for %-35s ... " "$desc ($script)"
            cd $SDE_PKGSRC/$pkg_dir
            
            cmd="sudo env https_proxy=$https_proxy http_proxy=$http_proxy pip install -r $script"
            start_log $SDE_LOGS/${step}-${script}.log $cmd
            if $cmd &>> $SDE_LOGS/${step}-${script}.log; then
                echo DONE
                result=0
            else 
                echo FAILED
                print_help_dependencies
                show_log $SDE_LOGS/${step}-${script}.log
                result=1
            fi
    
            cd $SDE
            return $result
        else
            echo "WARNING: Cannot find PIP requirements script $script" 
            echo "         in package directory \$SDE/$pkgsrc/$pkg_dir"
            echo "         This may happen if sde_build.sh script is too old "
            echo "         or too new for a given SDE version."
        fi
    else
        echo "WARNING: Cannot find package $pkg_name in \$SDE/$pkgsrc"        
    fi

    # If we got here, that means that nothing was done, either because
    # the package is not present or there was nothing to install
    echo "WARNING: Skipping the step <install_pkg_deps_pip $pkg_name>."
    echo "         Note: This may cause problems later..."
    return 0
}

install_binaries() {
    local result
    local cmd
    
    p4_compilers_dir=`package_dir p4-compilers`
    if [ -z $p4_compilers_dir ]; then
        echo "ERROR: p4-compilers package is missing"
        return 1
    fi

    tofino_model_dir=`package_dir tofino-model`
    if [ -z $p4_compilers_dir ]; then
        echo "ERROR: tofino-model package is missing"
        return 1
    fi

    #
    # Due to the fact that currently it is not possible to run
    # install_bin_pkgs.sh more than once, it is better to check
    # if it has already been run
    #
    if [ -f $SDE_INSTALL/lib/libavago.so.0 ]; then
        print_help_install_binaries
        return 1
    fi
    
    echo -n "Installing Binary Programs (install_bin_pkgs.sh)  ... "
    cd $SDE

    # Skip installing p4c dependencies. They should be installed at the
    # earlier steps separately
    cmd="./install_bin_pkgs.sh -b $build_arch -t $build_arch --no-p4c-deps"
    
    start_log $SDE_LOGS/${step}-install_bin_pkgs.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-install_bin_pkgs.log; then
        echo DONE
        result=0
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-install_bin_pkgs.log
        result=1
    fi

    return $result
}

#
# p4_lib_workaround
#
# This function fixes an installation problem introduced in SDE-8.4.0, where
# the files metadata.json and primitives.json got placed into an incorrect
# directory
p4_lib_workaround() {
    dir_840=$SDE_INSTALL/share/p4_lib
    dir_all=$SDE_INSTALL/share/p4_lib/tofino

    echo -n "Fixing \$SDE_INSTALL/share/p4_lib                  ... "
    if [ -f $dir_840/primitives.json ]; then
        mv $dir_840/primitives.json $dir_all
    fi
    
    if [ -f $dir_840/metadata.json ]; then
        mv $dir_840/metadata.json $dir_all
    fi
    echo DONE
    return 0
}

#
# Install p4i in /usr/bin (will change in the future)
#
install_p4i() {
    local p4i_dir
    local result
    local cmd

    if [ $with_p4i -eq 0 ]; then
        return 0
    fi

    p4i_dir=`package_dir p4i`
    if [ -z $p4i_dir ]; then
        cat <<EOF
WARNING: p4i package not found and thus not be installed
EOF
        return 0
    fi
    p4i_dir="$SDE_PKGSRC/$p4i_dir"
    
    if [ $build_arch != "x86_64" ]; then
        cat <<EOF
ERROR: p4i not installed, since it is only distributed for x86_64.
       Use --no-p4i to avoid this problem
EOF
        return 1
    fi
    
    # This might change in the future
    p4i_binary="p4i-`cat $p4i_dir/RELEASE`.linux"
    
    if [ ! -f $p4i_dir/$p4i_binary ]; then
        cat <<EOF
ERROR: $p4i_binary binary not found in p4i package directtory.
       Please, check your installation
EOF
        return 1
    fi

    echo -n "Installing p4i                                    ... "
    cmd="install -m 755 $p4i_dir/$p4i_binary $SDE_INSTALL/bin/p4i"
    start_log $SDE_LOGS/${step}-install_p4i.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-install_p4i.log; then
        echo DONE
        result=0
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-install_p4i.log
        result=1
    fi

    echo -n "Installing xdg-open in \$SDE_INSTALL/bin           ... "
    if xdg_open=`which xdg-open`; then
        if ln -s $xdg_open $SDE_INSTALL/bin; then
            echo DONE
        else
            echo FAILED
            cat <<EOF
WARNING: Could not link xdg-open utility into \$SDE_INSTALL/bin.
         p4i will work, but you will need to start the browser manually 
         and point it to the URL, diplayed by p4i upon startup
EOF
        fi
    else
        echo "NOT FOUND"
        cat <<EOF
WARNING: xdg-open utility is not found in your system. Usually it is installed
         as a part of xdg-utils package or similar. p4i will work, but you
         will need to start the browser manually and point it to the URL,
         diplayed by p4i upon startup
EOF
    fi

    return 0            
}

generate_configure() {
    echo "Generating ./configure scripts in package directories"
    start_log $SDE_LOGS/${step}-autogen.log "./autogen.sh or autoreconf -fi"
    for x in $SDE_PACKAGE_LIST; do
        package=`echo $x | cut -d: -f1`
        pkg_dir=`package_dir $package`
        pushd $pkgsrc/$pkg_dir > /dev/null
        if [ -f configure.ac ]; then
                printf "Running autoconf in %-15s ... " $pkg_dir
                if [ ! -f configure -o $force_autogen -eq 1 ]; then
                    if [ -f autogen.sh ]; then 
                        ./autogen.sh &>> $SDE_LOGS/${step}-autogen.log
                    else 
                        autoreconf -fi &>> $SDE_LOGS/${step}-autogen.log
                    fi
                    echo DONE
                else
                    echo "./configure exists. Skipping"
                fi
        else
            echo "$pkg_dir does not use Autoconf. Skipping"
        fi
        popd > /dev/null
    done
}

build_pkg() {
    local pkg_name=$1; shift
    local cmd
    local yes_no
    
    pkg_dir=`package_dir $pkg_name`
    if [ -z $pkg_dir ]; then
        echo "ERROR: Cannot find package $pkg_name in \$SDE/$pkgsrc"
        if [ $yes -ne 1 ]; then 
            read -p "Would you like to skip building this package [Y/n]? " \
                 yes_no
        else
            yes_no="Yes"
        fi

        case $yes_no in
            [Nn]*)
                echo "Stop"
                return 1 ;;
            *)
                echo "WARNING: Skipping the step <build_pkg $pkg_name>."
                echo "         Note: This may cause problems later..."
                return 0
        esac
    fi

    cd $SDE_BUILD
    rm -rf $pkg_name
    mkdir  $pkg_name
    cd     $pkg_name

    printf "Building Package %-15s ... " $pkg_name

    echo -n "CONFIGURE ... "
    cmd="../../$pkgsrc/${pkg_dir}/configure --prefix=$SDE_INSTALL"
    start_log $SDE_LOGS/${step}-${pkg_name}.configure.log $cmd "$@"
    if $cmd "$@" &>> $SDE_LOGS/${step}-${pkg_name}.configure.log; then
        echo -ne "\b\b\b\b"
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${pkg_name}.configure.log
        cd $SDE
        return 1
    fi

    echo -n "MAKE ... "
    cmd="make -j${jobs}"
    start_log $SDE_LOGS/${step}-${pkg_name}.make.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${pkg_name}.make.log; then
        echo -ne "\b\b\b\b"
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${pkg_name}.make.log
        cd $SDE
        return 1
    fi

    echo -n "INSTALL ... "
    cmd="make install"
    start_log $SDE_LOGS/${step}-${pkg_name}.install.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${pkg_name}.install.log; then
        echo DONE
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${pkg_name}.install.log
        cd $SDE
        return 1
    fi

    cd $SDE
    return 0
}

build_python_pkg() {
    local pkg_name=$1; shift
    local cmd
    local yes_no

    local pkg_dir=`package_dir $pkg_name`
    if [ -z $pkg_dir ]; then
        echo "ERROR: Cannot find package $pkg_name in \$SDE/$pkgsrc"
        if [ $yes -ne 1 ]; then
            read -p "Would you like to skip building this package [Y/n]? " \
                 yes_no
        else
            yes_no="yes"
        fi

        case $yes_no in
            [Nn]*)
                echo "Stop"
                return 1
                ;;
            *)
                echo "WARNING: Skipping the step <build_python_pkg $pkg_name>."
                echo "         Note: This may cause problems later..."
                return 0
        esac
    fi

    cd $SDE/$pkgsrc/$pkg_dir
    cmd="python setup.py install --prefix=$SDE_INSTALL --single-version-externally-managed --record install.txt"
    start_log $SDE_LOGS/${step}-${pkg_name}.install.log $cmd "$@"
    printf "Building Package %-15s ... " $pkg_name
    if $cmd "$@" &>> $SDE_LOGS/${step}-${pkg_name}.install.log; then 
        echo DONE
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${pkg_name}.install.log
        cd $SDE
        return 1
    fi

    cd $SDE
    return 0
}

#
# build_switch_pkg <pkg>
#
# This is an integrated function that builds switch or switch-p4-16
# package
#
build_switch_pkg() {
    case $switch_pkg in
        switch)
            process_switch_profile
            # If switch-p4-16 was previously buit, we need to uninstall it
            uninstall_pkg switch-p4-16 
            build_pkg     switch \
                                   --with-tofino                 \
                                   --with-p4c=$switch_compiler   \
                                   --with-switchapi              \
                                   --with-switchsai              \
                                   P4JOBS=`get_ncpus`            \
                                   P4FLAGS="$switch_p4flags"     \
                                   $SWPROF                       \
                                   enable_thrift=$thrift         \
                                   $switch_extra_flags
            ;;
        switch-p4-16)
            process_switch16_profile
            # If switch (p4-14) was previously buit, we need to uninstall it
            uninstall_pkg switch

            # Due to a bug in SDE-8.4.0, additional compiler flags (P4FLAGS) 
            # are not passed to the P4 compiler (bf-p4c). 
            # As a workaround, we pass "-g" via P4PPFLAGS. Unfortunately,
            # other parameters cannot be passed because P4PPFLAGS is also
            # passed to GCC
            # The proper workaround is pass P4FLAGS to the make, but this
            # requires a lot of changes to the basic infrastructure of this
            # script.
            # Also, due to another bug, building for multiple platforms is
            # not supported in SDE-8.4.0
            build_pkg   switch-p4-16 \
                                   --with-tofino                 \
                                   $switch_extra_platforms       \
                                   P4JOBS=`get_ncpus`            \
                                   P4FLAGS="$switch_p4flags"     \
                                   P4PPFLAGS="-g"                \
                                   enable_thrift=$thrift         \
                                   $switch_extra_flags
            print_help_switch_p4_16
            ;;
    esac    
}

#
# This functon builds an individual Tofino example. It expects 
# $SDE_EXAMPLES to point to the p4-examples package
# $SDE_P4_BUILD to point to the p4-build    package
#
build_tofino_example() {
    local ex_name=$1
    shift
    
    cd $SDE_BUILD
    rm -rf examples/$ex_name
    mkdir -p examples/$ex_name
    cd examples/$ex_name

    printf "Building Example %-25s ... " $ex_name
    cmd="$SDE_P4_BUILD/configure                                    \
              --prefix=$SDE_INSTALL                                 \
              --with-tofino enable_thrift=$thrift                   \
              P4_PATH=$SDE_EXAMPLES/programs/$ex_name/${ex_name}.p4 \
              P4_NAME=$ex_name                                      \
              P4JOBS=`get_ncpus`"
    start_log $SDE_LOGS/${step}-${ex_name}.configure.log $cmd "$@"
    echo -n "CONFIGURE ... "
    if $cmd "$@" &>> $SDE_LOGS/${step}-${ex_name}.configure.log; then
        echo -ne "\b\b\b\b"
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${ex_name}.configure.log
        cd $SDE
        return 1
    fi

    #echo -n "   Building Example $ex_name in \$SDE/build/examples/$ex_name ... "
    echo -n "MAKE ... "
    cmd="make -j${jobs}"
    start_log $SDE_LOGS/${step}-${ex_name}.make.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${ex_name}.make.log; then
        echo -ne "\b\b\b\b"
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${ex_name}.make.log
        cd $SDE
        return 1
    fi

    #echo -n " Installing Example $ex_name in \$SDE_INSTALL ... "
    echo -n "INSTALL ... "
    cmd="make install"
    start_log $SDE_LOGS/${step}-${ex_name}.install.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${ex_name}.install.log; then
        echo DONE
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${ex_name}.install.log
        cd $SDE
        return 1
   fi

   cd $SDE
   return 0
}

#
# This function builds all examples for Tofino (p4-examples/programs)
#
build_tofino_examples() {
    SDE_EXAMPLES=`package_dir p4-examples`
    if [ -z $SDE_EXAMPLES ]; then
        if [ $list_steps -ne 0 ]; then
            echo "WARNING: p4-example package has not be unpacked yet"
            echo "         The exact list of examples will be determined later"
        else
            echo "WARNING: p4-examples package not found."
            echo "         Skipping building the examples"
        fi
        return 0
    else
        SDE_EXAMPLES=$SDE_PKGSRC/$SDE_EXAMPLES
    fi

    SDE_P4_BUILD=`package_dir p4-build`
    if [ -z $SDE_P4_BUILD ]; then
        echo "WARNING: p4-build package not found."
        echo "         Skipping building the examples"
        exit 0
    else
        SDE_P4_BUILD=$SDE_PKGSRC/$SDE_P4_BUILD
    fi

    local extra_args
    local extra_p4flags

    for x in $SDE_EXAMPLES/programs/*; do
        unset extra_platforms
        unset extra_p4flags
 
        local ex_name=`basename $x`
        if [ -f $x/${ex_name}.p4 ]; then
            # Case statements below help us to deal with special cases

            # Add special P4FLAGS when compiling for Tofino
            case $ex_name in 
                basic_ipv4|exm_direct*|exm_indirect_1|exm_smoke_test|meters|multi_device)
                    extra_p4flags='--placement pragma'
                    ;;
                *)
                    ;;
            esac

            # Special cases for programs that might not work
            case $ex_name in
                ipv4_checksum)
                    ;;
                *)
                    step build_tofino_example $ex_name             \
                         P4FLAGS="$default_p4flags $extra_p4flags" \
                         $extra_platforms
                    ;;
            esac
        fi
    done
}

#
# This functon builds an individual P4_16 TNA example. It expects 
# $SDE_EXAMPLES to point to the p4-examples package
# $SDE_P4_BUILD to point to the p4-build    package
#
build_tna_example() {
    local ex_name=$1
    shift
    
    cd $SDE_BUILD
    rm -rf examples/$ex_name
    mkdir -p examples/$ex_name
    cd examples/$ex_name

    printf "Building P4_16/TNA Example %-25s ... " $ex_name
    cmd="$SDE_P4_BUILD/configure                                    \
              --prefix=$SDE_INSTALL                                 \
              --with-tofino --with-p4c                              \
              P4_PATH=$SDE_EXAMPLES/p4_16_programs/$ex_name/${ex_name}.p4 \
              P4_NAME=$ex_name                                      \
              P4_VERSION=p4-16 P4_ARHITECTURE=tna                   \
              P4PPFLAGS=-I$SDE_EXAMPLES/p4_16_programs              \
              P4JOBS=`get_ncpus`"
    start_log $SDE_LOGS/${step}-${ex_name}.configure.log $cmd "$@"
    echo -n "CONFIGURE ... "
    if $cmd "$@" &>> $SDE_LOGS/${step}-${ex_name}.configure.log; then
        echo -ne "\b\b\b\b"
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${ex_name}.configure.log
        cd $SDE
        return 1
    fi

    #echo -n "   Building Example $ex_name in \$SDE/build/examples/$ex_name ... "
    echo -n "MAKE ... "
    cmd="make -j${jobs}"
    start_log $SDE_LOGS/${step}-${ex_name}.make.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${ex_name}.make.log; then
        echo -ne "\b\b\b\b"
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${ex_name}.make.log
        cd $SDE
        return 1
    fi

    #echo -n " Installing Example $ex_name in \$SDE_INSTALL ... "
    echo -n "INSTALL ... "
    cmd="make install"
    start_log $SDE_LOGS/${step}-${ex_name}.install.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${ex_name}.install.log; then
        echo DONE
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${ex_name}.install.log
        cd $SDE
        return 1
   fi

   cd $SDE
   return 0
}

#
# This function builds all examples for P4_16/TNA
# (p4-examples/p4_16_programs)
#
build_tna_examples() {
    SDE_EXAMPLES=`package_dir p4-examples`
    if [ -z $SDE_EXAMPLES ]; then
        if [ $list_steps -ne 0 ]; then
            echo "WARNING: p4-example package has not be unpacked yet"
            echo "         The exact list of examples will be determined later"
        else
            echo "WARNING: p4-examples package not found."
            echo "         Skipping building the examples"
        fi
        return 0
    else
        SDE_EXAMPLES=$SDE_PKGSRC/$SDE_EXAMPLES
    fi

    SDE_P4_BUILD=`package_dir p4-build`
    if [ -z $SDE_P4_BUILD ]; then
        echo "WARNING: p4-build package not found."
        echo "         Skipping building the examples"
        exit 0
    else
        SDE_P4_BUILD=$SDE_PKGSRC/$SDE_P4_BUILD
    fi

    local extra_args
    local extra_p4flags

    for x in $SDE_EXAMPLES/p4_16_programs/*; do
        unset extra_platforms
        unset extra_p4flags
 
        local ex_name=`basename $x`
        if [ -f $x/${ex_name}.p4 ]; then
            # Case statements below help us to deal with special cases

            # Add special P4FLAGS when compiling for Tofino
            case $ex_name in 
                #program1|program2)
                #    extra_p4flags='extra compiler flags if needed'
                #    ;;
                *)
                    ;;
            esac

            # Special cases for programs that might not work
            case $ex_name in
                common)
                      ;;
                *)
                    step build_tna_example $ex_name                 \
                         P4FLAGS="$default_p4c_flags $extra_p4flags" \
                         $extra_platforms
                    ;;
            esac
        fi
    done
}

#
# This function builds Doxygen documentation for bf-drivers
#
build_docs_bf_drivers() {
    local cmd
    
    if [ ! -d $SDE_BUILD/bf-drivers ]; then
        echo "ERROR: this step requires you to build bf-drivers first"
        return 1
    fi
    
    cd $SDE_BUILD/bf-drivers
    grep -q "^DOXYGEN = .\+" Makefile
    if [ $? != 0 ]; then 
        echo "ERROR: Doxygen was not present during bf-drivers configure"
        echo "       Install Doxygen (e.g. sudo apt-get install doxygen)"
        echo "       and re-run \"build_pkg bf-drivers\" step."
        return 1
    fi

    printf "Building Doxygen Docs for %-15s ... " bf-drivers
    cmd="make doc"
    start_log $SDE_LOGS/${step}-bf-drivers-docs.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-bf-drivers-docs.log; then
        echo DONE
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-bf-drivers-docs.log
        cd $SDE
        return 1
    fi

    cd $SDE
    return 0    
}

#
# This function builds Doxygen documentation for bf-drivers
#
build_docs_switch() {
    local cmd

    if [ ! -d $SDE_BUILD/$switch_pkg ]; then
        echo "ERROR: this step requires you to build $switch_pkg package first"
        return 1
    fi
    
    cd $SDE_BUILD/$switch_pkg
    if [ ! -d doc ]; then
        cat <<EOF
WARNING: \$SDE/build/${switch_pkg}/doc directory is missing. Probably, 
         this is an old SDE version. Step skipped

EOF
        return 0
    fi

    cd doc
    
    grep -q "^DOXYGEN = .\+" Makefile
    if [ $? != 0 ]; then
        cat <<EOF
INFO: Doxygen was not present during $switch_pkg package configure
      Install Doxygen (e.g. sudo apt-get install doxygen)
      and re-run "build_switch_pkg" step.
EOF
        return 1
    fi

    printf "Building Doxygen Docs for %-15s ... " $switch_pkg
    cmd="make doc"
    start_log $SDE_LOGS/${step}-${switch_pkg}-docs.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-${switch_pkg}-docs.log; then
        echo DONE
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-${switch_pkg}-docs.log
        cd $SDE
        return 1
    fi

    cd $SDE
    return 0    
}

#
# This function builds cscope database for a P4 program in a given directory
# 
cscope_p4() {
    local p4_dir=$1
    shift

    if which cscope > /dev/null; then 
        echo -n "Building cscope database for P4 program in $p4_dir ... "
        cd $SDE_PKGSRC/$p4_dir
        find . -name '*.p4' -o -name '*.h' > cscope.files
        cscope -bk -I $SDE_INSTALL/share/p4_lib
        echo DONE
    else
        echo "INFO: cscope is not found in the system. Step skipped"
    fi

    cd $SDE
    return 0
}

#
# This function builds cscope database for a P4 program included in a package
#
cscope_p4_pkg() {
    local pkg_name=$1
    shift

    local pkg_dir=`package_dir $pkg_name`
    if [ -z $pkg_dir ]; then
        echo "WARNING: Cannot find package $pkg_name in \$SDE/$pkgsrc"
        echo "         Skipping the step <cscope_p4_pkg $pkg_name>."
        return 0
    fi
    cscope_p4 $pkg_dir/p4src
}

#
# This function build cscope database for SDE. This one only considers C code
# and not C++ and thus is not useful for browsing Thrift
# server/client code, for example.
#
cscope_sde() {
    cd $SDE
    
    if which cscope > /dev/null; then
        find . -name '*.[ch]' -type f > cscope.files
        cscope -b
    else
        echo "INFO: cscope is not found in the system. Step skipped"
    fi

    return 0
}

#
# The function checks if a particular profile is supported by switch.p4
# Most probably the function can be extended to switch-p4-16, but currently
# switch-p4-16 does not have any profiles.
#
check_switch_profile() {
    local profile_name=$1
    local pkg_dir
    shift

    pkg_dir=`package_dir switch`
    if [ -z $pkg_dir ]; then
        return 1
    fi

    profiles=`grep -r _PROFILE $SDE_PKGSRC/$pkg_dir/p4src |          \
              sed -e 's/^.*[^A-Z0-9_]\([A-Z0-9_]*_PROFILE\).*/\1/' | \
              sort | uniq`

    for p in $profiles; do
        if [ $p == $profile_name ]; then
            return 0
        fi
    done

    echo "ERROR: Profile $profile_name is not supported in $switch_pkg"
    echo "       Supported profiles are:"
    for p in $profiles; do
        echo "             $p"
    done
    return 1

}

#
# This function picks up profile-specific settings, namely:
#  -- the compiler (and thus default compiler flags)
#  -- Additional, profile-specific flags
#  -- Any other workarounds that might be reqired
process_switch_profile() {
    local pkg_dir
    
    #  Check switch profile. If not specified, use the default
    if  [ ! -z $switch_profile ]; then
        if check_switch_profile $switch_profile ; then
            echo Using profile $switch_profile for switch.p4
        else  # Incorrect profile
            exit 1
        fi
    else
        echo "Using default profile (DC_BASIC_PROFILE) for switch.p4"
        switch_profile=DC_BASIC_PROFILE
    fi

    SWPROF="P4PPFLAGS=-D${switch_profile}"

    #
    # Now it's time to figure out which compiler to use
    #
    pkg_dir=`package_dir switch`
    if [ -z $pkg_dir ]; then
        return 1
    fi
    
    configure_ac=$SDE_PKGSRC/$pkg_dir/configure.ac
    if [ ! -f $configure_ac ]; then
        cat <<EOF
ERROR: Cannot access configure.ac in the switch package. Most probably this 
       script is not compatible with the SDE version you are using.
EOF
        return 1
    fi

    # configure.ac file in the switch package directory contains a line
    # like this that we can use to get the list of profiles that are compiled
    # with bf-p4c by default
    # p4c_profiles="DC_BASIC_PROFILE ENT_DC_GENERAL_PROFILE MSDC_PROFILE"
    eval `grep ^p4c_profiles= $configure_ac`

    if [ -z $switch_compiler ]; then
        switch_compiler=p4c-tofino
        for p in $p4c_profiles; do
            if [ $p == $switch_profile ]; then
                switch_compiler=bf-p4c
                break;
            fi
        done
    fi

    case $switch_compiler in
        p4c-tofino)
            switch_p4flags=$default_p4flags
            ;;
        bf-p4c|p4c)
            switch_compiler="bf-p4c"
            switch_p4flags=$default_p4c_flags
            ;;
        *)
            print_help_compiler; exit 1;;
    esac

    # Here should go additional workarounds
    case $switch_profile in
        DC_MAXSIZES_PROFILE)
            switch_compiler="p4c-tofino"
            switch_p4flags="$default_p4flags --force-match-dependency"
            ;;
    esac

    echo "Using $switch_compiler to compile switch.p4"
    echo "Using additional compiler flags: $switch_p4flags"

    return 0
}

#
# switch-p4-16 package doesn't have profiles yet. We'll do some basic
# checks here
process_switch16_profile() {
    if [ ! -z $switch_profile ]; then
       cat <<EOF
ERROR: switch-p4-16 does not support any profiles yet
EOF
       return 1
    fi

    case $switch_compiler in
        bf-p4c|p4c|"")
            switch_compiler="bf-p4c"
            switch_p4flags=$default_p4c_flags
            ;;
        *) cat <<EOF
ERROR: switch-p4-16 can only be compiled with bf-p4c. $switch_compiler is
       not supported
EOF
           return 1
           ;;
    esac

    if [ ! -z $switch_extra_platforms ]; then
        cat <<EOF

WARNING: Due to a bug in SDE-8.4.0, building switch-p4-16 for multiple
         platforms is not supported. If you want to build switch-p4-16
         for another platform ($switch_extra_platforms), you need to do 
         it manually. This script will build switch-p4-16 for Tofino only.

EOF
        switch_extra_platforms=
    fi
    
    echo "Using $switch_compiler to compile switch.p4"
    echo "Using additional compiler flags: $switch_p4flags"
    cat <<EOF

WARNING: Due to a bug in SDE-8.4.0, additional compiler flags (P4FLAGS) are
         NOT passed to $switch_compiler. 

         This script uses a workaround to pass "-g" so that you can see the 
         visualizations despite this bug. 

         If you'd like to see graphs as well, you will need to rebuild 
         switch-p4-16 package and pass P4FLAGS on the make's command line
         like so:
         ===============
         cd $SDE_BUILD/switch-p4-16
         make clean
         make -j $jobs P4FLAGS="$switch_p4flags" && make install
         ===============

EOF
    return 0
}

#
# uninstall_pkg <package>
# This function explicitly uninstalls previously built package.
# This is mostly needed, because switch and switch-p4-16 can't coexist
uninstall_pkg() {
    local pkg
    local cmd
    local result
    
    pkg=$1; shift

    if [ ! -f $SDE_BUILD/$pkg/Makefile ]; then
        return 0
    fi

    echo -n "Uninstalling $pkg ... "
    cmd="make -j $jobs -C $SDE_BUILD/$pkg uninstall"
    start_log $SDE_LOGS/${step}-uninstall-${pkg}.log $cmd
    if $cmd &>> $SDE_LOGS/${step}-uninstall-${pkg}.log; then
        echo DONE
        result=0
    else
        echo FAILED
        show_log $SDE_LOGS/${step}-uninstall-${pkg}.log
        result=1
    fi

    return $result
}

#
# Function context_json_schema
#
# This function runs the compiler against a trivial P4 program to produce
# context.json schema file. This file is not needed by any SDE components,
# but is useful for those who plan to develop their own context.json-based
# tools
context_json_schema() {
    cd $SDE_BUILD
    rm -rf schema
    mkdir -p schema
    cd schema

    cat > schema.p4 <<EOF
/* This is a minimal P4 program */
#include <tofino/intrinsic_metadata.p4>
parser start {
    return ingress;
}

control ingress {
}
EOF
    echo -n "Generating schema.json ... "
    cmd="p4c-tofino --context-json-schema schema.p4"
    start_log $SDE_LOGS/${step}-schema.log $cmd
    echo -n "COMPILE ... "
    if $cmd &>> $SDE_LOGS/${step}-schema.log; then
        echo -en "\b\b\b\b"
    else
        echo FAILED
        show_log  $SDE_LOGS/${step}-schema.log
        cd $SDE
        return 1
    fi

    echo -n "INSTALL ... "
    cmd="cp schema.tofino/context/*schema.json \
          $SDE_INSTALL/share/p4_lib/tofino"
    echo $cmd >> $SDE_LOGS/${step}-schema.log
    if $cmd &>> $SDE_LOGS/${step}-schema.log; then
        echo DONE
    else
        echo FAILED
        show_log  $SDE_LOGS/${step}-schema.log
        cd $SDE
        return 1
    fi
    
    cd $SDE
    return 0
}

#
# Function dma_setup
#
dma_setup() {
    echo "Setting up DMA Memory Pool"
    nr_hugepages=`sysctl vm.nr_hugepages | cut -d\  -f 3`
    if [ $nr_hugepages -eq 0 ]; then
        if [ -d /mnt/huge ]; then
            cat <<EOF
ERROR: /mnt/huge directory is already present. Please, remove that directory
       first and then run dma_setup.sh script manually, e.g.
            sudo rmdir /mnt/huge
            sudo \$SDE_INSTALL/bin/dma_setup.sh
EOF
            return 1
        else
            cat <<EOF
INFO: Setting up HUGEPAGES for the DMA Memory Pool. This requires root access
EOF
            if sudo $SDE_INSTALL/bin/dma_setup.sh; then
                echo "INFO: HUGEPAGES setup successfully"
                return 0
            else
                echo "ERROR: HUGEPAGES setup failed. Run dma_setup.sh script manually"
                return 1
            fi
        fi
    elif [ $nr_hugepages -ge 128 ]; then
         echo "INFO: vm.nr_hugepages = $nr_hugepages. Good"
         echo -n "INFO: Checking mountpoint for hugetlbfs ... "
         if findmnt -t hugetlbfs | grep -q hugetlbfs; then
             echo "hugetlbfs is already mounted. Good"
             echo "INFO: Your DMA Memory pool is already set up corectly"
        else
            if [ -d /mnt/huge ] ; then
                echo "hugetlbfs is not mounted."
                cat <<EOF

WARNING: /mnt/huge is present, but does not appear to be mounted as hugetlbfs. 
         We recommend removing the directory (provided that there is nothing
         vital in there) and then running dma_setup.sh script
EOF
            else
                cat <<EOF

INFO: Setting up HUGEPAGES for the DMA Memory Pool. This requires root access
EOF
                if sudo $SDE_INSTALL/bin/dma_setup.sh; then
                    echo "INFO: HUGEPAGES setup successfully"
                    return 0
                else
                    echo "ERROR: HUGEPAGES setup failed. Run dma_setup.sh script manually"
                    return 1
                fi
            fi
        fi
    else
        echo "INFO: vm.nr_hugepages = $nr_hugepages"
        cat <<EOF
WARNING: the number of HUGEPAGES recommended for SDE is 128. Please, check
         your configuration. You might need to re-run dma_setup.sh manually
EOF
    fi
}


############################################################################
##########################     M A I N    ##################################
############################################################################

#
# Option Processing
#
CMDLINE="$@"

opts=`getopt -o s:e:S:j:t:g:nhacrvq       \
             -l version                   \
             -l help                      \
             -l jobs:                     \
             -l no-bmv2                   \
             -l with-bmv2                 \
             -l no-deps                   \
             -l do-not-check-deps         \
             -l do-not-check-version      \
             -l no-bf-platforms           \
             -l no-dma-setup              \
             -l switch-pkg:               \
             -l switch-compiler:          \
             -l switch-extra-platforms:   \
             -l switch-profile:           \
             -l switch-extra-flags:       \
             -l examples-extra-platforms: \
             -l with-examples             \
             -l no-examples               \
             -l bf-drivers-extra-flags:   \
             -l with-alpha                \
             -l no-p4i                    \
             -l yes                       \
             -l quick                     \
             -- "$@"`

if [ $? != 0 ]; then
  print_help
  exit 1
fi
eval set -- "$opts"

while true; do
    case "$1" in
        -a) force_autogen=1; shift 1;;
        -c) force_cleanup=1; shift 1;;
        -s) first_step=$2;   shift 2;;
        -e) last_step=$2;    shift 2;;
        -S) step_name=$2;    shift 2;;
        -t) thrift=$2;       shift 2;;
        -g) grpc=$2;         shift 2;;
        -j|--jobs) jobs=$2;  shift 2;;
        -n) list_steps=1;    shift 1;;
        -r) real_hardware=1; shift 1;;
        --no-deps)                  install_deps=0;            shift 1;;
        --do-not-check-deps)        sanity_deps_check=0;       shift 1;;
        --do-not-check-version)     check_version=0;           shift 1;;
        --no-bmv2)                                             shift 1;;
        --with-bmv2)                print_help_bmv2;            exit 1;;
        --no-bf-platforms)          install_bf_platforms=0;    shift 1;;
        --no-dma-setup)             do_dma_setup=0;            shift 1;;
        --switch-pkg)
            case $2 in
                switch|14|[pP]4[_-]14)
                    switch_pkg="switch";;
                switch-p4[_-]16|16|[pP]4[_-]16)
                    switch_pkg="switch-p4-16";;
                [Nn][Oo]|[Nn][Oo][Nn][Ee])
                    switch_pkg="none";;
                *) print_help_switch_pkg $2; exit 1;;
            esac;                                              shift 2;;
        --switch-compiler)
            case $2 in
                p4c-tofino)
                    switch_compiler="p4c-tofino";;
                bf-p4c|p4c)
                    switch_compiler="bf-p4c";;
                *) print_help_compiler $2; exit 1;;
            esac;                                              shift 2;;
        --switch-extra-platforms)   switch_extra_platforms=$2; shift 2;;
        --switch-profile)           switch_profile=$2;         shift 2;;
        --switch-extra-flags)       switch_extra_flags=$2;     shift 2;;
        --with-examples)            with_examples=1;           shift 1;;
        --no-examples)              with_examples=0;           shift 1;;
        --with-alpha)               with_alpha=1;              shift 1;;
        --examples-extra-platforms) switch_extra_platforms=$2; shift 2;;
        --bf-drivers-extra-flags)   bf_drivers_extra_flags=$2; shift 2;;
        --no-p4i)                   with_p4i=0;                shift 1;;
        --yes)                      yes=1;                     shift 1;;
        -q|--quick) quick=1;                                   shift 1;;
        -v|--version) print_version; exit 0;;
        -h|--help)    print_help; exit 0;;
        --) shift; break;;
    esac
done

if [ $with_alpha -ne 0 ]; then
    cat <<EOF

********************************** ATTENTION **********************************

You selected to build some alpha-quality components, not supported 
by Customer Engineering. 

If you experience any problems, please contact sde-alpha@barefootnetworks.com

To get better support, please ensure that the errors you see can be reproduced
by executing the same steps manually as outlined in the README files. And do 
not forget to include full logs.

Also, please note that as of today only Ubuntu-16.04 is supported.

*******************************************************************************

EOF
    if [ $yes -ne 1 ]; then
        read -p "Do you want to proceed [y/N]? " yes_no
    else
        yes_no="yes"
    fi
    case $yes_no in
        [Yy]*) ;;
        *) echo "Alpha build cancelled"; exit 1
    esac
fi

if [ $quick -eq 1 ]; then
    install_deps=0
    force_autogen=0
    with_examples=0
fi

if [ $real_hardware -ne 1 ]; then
    install_bf_platforms=0
    switch_extra_flags="$switch_extra_flags --with-cpu-veth"
fi

#
# Here we go...
#
check_environment

if [ `pwd` != $SDE ]; then 
    echo "WARNING: Your SDE environment variable is set to $SDE,"
    echo "         but your current directory is " `pwd`
fi

cd $SDE

if [ $force_cleanup -ne 0 ]; then
    if [[ $first_step -le 1 && -z $step_name ]]; then
        cleanup_dirs $SDE_INSTALL $SDE_BUILD $SDE_LOGS
    else
        cat <<EOF
ERROR: You specified -c (force cleanup) parameter together with either -s
       (start_step) or -S (step_name) parameters. It probably doesn't make
       sense to clean the SDE directory and then execute only some steps and 
       not from the very beginning.
EOF
        exit 1
    fi
fi

if [ $list_steps -eq 0 ]; then
    echo "Making sure \$SDE/$build and \$SDE/$logs are present"
    mkdir -p $SDE_BUILD
    mkdir -p $SDE_LOGS
fi

###############################################################
#
# Below go individual steps, required to build SDE and examples
#
###############################################################
step=1

section "Preparation steps"

step  untar_packages

#
# Avoid installing dependencies on the Real hardware, since it might
# not be connected to the internet
#
if [ $install_deps -eq 1 ]; then
    step  install_deps         SDE        install_min_deps.sh

    if [ $thrift == "yes" ]; then 
        step  install_deps         Thrift     install_thrift_deps.sh
    fi
    
    if [ $grpc == "yes" ]; then 
        step  install_deps     gRPC       install_grpc_deps.sh -j $jobs
    fi

    step  install_deps         p4c        install_p4c_deps.sh
    step  install_deps         PTF        install_ptf_deps.sh
    step  install_pkg_deps_pip p4-hlir    p4-hlir       requirements.txt

    # Each switch package needs its own dependencies. We install them both
    # unconditionally, but in case there are problems, we can do it separately
    step install_pkg_deps Switch       switch       install_switch_deps.sh
    step install_pkg_deps Switch-P4_16 switch-p4-16 install_bf_switch_deps.sh
    
    step  install_pkg_deps     Diags      bf-diags      install_diag_deps.sh

    if [ $install_bf_platforms -eq 1 ]; then
        step  install_pkg_deps    Platform   bf-platforms  install_pltfm_deps.sh
    fi
fi

#
# It is better to check the dependencies unconditionally, even if we just
# installed them, just to make sure there were no installation problems
#
# Note, that this is not a step, so that this check is performed unconditionally
if [ $sanity_deps_check -ne 0 ]; then
    check_deps
fi


step  install_binaries
step  p4_lib_workaround
step  install_p4i

if [ $force_autogen -ne 0 ]; then
    step  generate_configure
fi

section "Building Packages in $SDE_BUILD"

step  build_pkg        bf-syslibs
step  build_pkg        bf-utils

step  build_pkg        bf-drivers                   \
                           enable_thrift=$thrift    \
                           enable_grpc=$grpc        \
                           "$bf_drivers_extra_flags"

step  build_pkg        ptf-modules

step  build_python_pkg p4-hlir 

if [ $quick -eq 0 ]; then
    step  build_switch_pkg $switch_pkg

    step  build_pkg        bf-diags                            \
                                    --with-tofino              \
                                    P4JOBS=`get_ncpus`         \
                                    P4FLAGS="$default_p4flags" \
                                    enable_thrift=$thrift
fi

if [ $with_examples -eq 1 ]; then 
    section "Building Tofino Examples in \$SDE_BUILD/examples"
    
    step  build_pkg            p4-examples 
    build_tofino_examples      # No "step" here -- it is inside the function

    section "Building P4_16/TNA Examples in \$SDE_BUILD/examples"
    build_tna_examples
fi

section "Additional Convenience Steps"

#
# Build Doxygen documentation if doxygen is present
#
if which doxygen > /dev/null; then
    step build_docs_bf_drivers
    if [ $quick -eq 0 ]; then
        if [ $switch_pkg != none ]; then
            step build_docs_switch
        fi
    fi
fi

#
# Build cscope Databases if cscope is present
#
if which cscope > /dev/null; then
    if [ $quick -eq 0 ]; then
        step cscope_p4_pkg switch
        step cscope_p4_pkg switch-p4-16
        step cscope_sde
    fi
fi

#
# Produce context.json schema
#
if [ $quick -eq 0 ]; then
    step context_json_schema
fi

#
# Perform DMA setup
#
if [ $do_dma_setup != 0 ]; then
    step dma_setup
fi

if [ $real_hardware -eq 1 -a $install_bf_platforms -eq 1 ]; then
    print_help_bf_platforms
fi
