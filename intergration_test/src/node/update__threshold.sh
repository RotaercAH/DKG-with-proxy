#!/bin/bash

t=3
n=5

current_path=$(pwd)

folder_num=$(ls -lA | grep "^d" | wc -l)

for ((i=1;i<=folder_num;i++)); do

	sed -i "5s/.*/      \"threshold\":$t,/" "$current_path/node$i/config/config_file/node_config.json"
	
	sed -i "6s/.*/      \"share_counts\":$n/" "$current_path/node$i/config/config_file/node_config.json"
done
	
