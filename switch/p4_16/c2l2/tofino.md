# How to run P4 programs in Tofino Switch

In this doc, we will show how to run P4 program in both simulator and real Tofino
hardware.

## Run P4 in Tofino Emulator

First, create a directory in `$SDE/pkgsrc/p4-examples/programs/`:

```
cd $SDE/pkgsrc/p4-examples/programs/
mkdir <program-name>
```

Copy your P4 program to the `<program-name>` folder,
and rename it to `<program-name>.p4`.

Then, create a `<program-name>.conf` file in `$SDE/install/share/p4/targets/tofino/`
You can find some templates file in this folder, e.g., `basic_switching.conf`.

Finally, run these commands to start running your program in Tofino emulator:

```
# In terminal 1:
cd $SDE
./sde_build.sh -S <program-name> --with-examples --no-bmv2
sudo $SDE_INSTALL/bin/veth_setup.sh
./run_tofino_model.sh -p <program-name>

# In terminal 2:
./run_switchd.sh -p <program-name>
```

You will see a command line prompt in terminal 2.

To run the control plane program: after the terminal 2 command completes
(i.e. you see a command line prompt in terminal 2)
run the following:

```
# In terminal 3:
./utils/run_pd_rpc.py --target asic-model -p <program-name> <absolute_path_to_ctrpln_progs>/setup.py
```

## Run P4 in Tofino Hardware

First, log into the Tofino Wedge 100B switch.
```
ssh root@128.42.61.5
```

Then run those commands below to build and run the program:

```
cd $SDE               # bf-sde-8.2.0 or bf-sde-8.4.0
source set_sde.sh

# compile your program
./p4_build.sh <program-name>.p4

# Load and run your program
# Note that <p4-program> has no .p4 postfix
./run_switchd.sh -p <program-name>
```

Enable all ports in the command line prompt:

```
bfshell> ucli
bf-sde> pm

# go back to previous directory
bf-sde.pm> ..

# add all ports:
bf-sde.pm> port-add -/- 25G NONE

#enable all ports:
bf-sde.pm> port-enb -/-
```

If you have a control plane program to run, open another terminal:
```
# Terminal 2:
./tools/run_pd_rpc.py --target asic-model -p <program-name> <absolute_path_to_ctrpln_progs>/setup.py
```

If you want to run the packet generator, open another terminal:
```
# Terminal 3:
./run_p4_tests.sh -p <program-name> -t <absolute_path_to_the_directory_containing_test.py>
```

## Build `P4_16` programs in Tofino Hardware

### Use `p4_build.sh` to build your own program

The easiest way is to use `p4_build.sh`:

```
# compiling the program
./p4_build.sh <program-name>.p4
# load and run the program
./run_switchd.sh -p <program-name>
```

This script could automatically distinguish between `P4_14` and `P4_16`, see
the script for more details.


### Building `P4_16` examples

See page 8 in [SDE 8.4 Release Note](https://bfnsde.s3.amazonaws.com/8.4.0-002_SDE_ReleaseNotes.pdf?Signature=7tjSzBP1N6d60BVHuXMvyZ4eZL0%3D&Expires=1548359667&AWSAccessKeyId=AKIAJU3GJYWNUYTZG43A&x-amz-meta-org_name=Public&x-amz-meta-acl_tags=sla&x-amz-meta-acl=sla)
