cmd_/home/parallels/Soze_Linux/modules.order := {   echo /home/parallels/Soze_Linux/soze.ko; :; } | awk '!x[$$0]++' - > /home/parallels/Soze_Linux/modules.order
