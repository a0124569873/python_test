#!/bin/bash
#
# Copyright 6WIND, 2010, All rights reserved.

# cmdline boot_option
# 
# Return 0 if boot_option is found on kernel command-line and output its
# value to stdout if it has one. If boot_option is found multiple times,
# only show the last instance.
#
# Example:
#
# if FP_MASK=`cmdline fp_mask`; then
#   ...
# fi

cmdline() {
	local line
	local param
	local ret=1
	local value=''
	[ -z "${1}" ] && return 1
	while read -r line
	do
		[ -z "${line}" ] && continue
		for param in ${line}
		do
			case "${param}" in
			"${1}="*)
				ret=0
				value="${param#*=}"
				;;
			"${1}")
				ret=0
				;;
			esac
		done
	done < '/proc/cmdline' || return 2 # /proc not mounted?
	[ -z "${value}" ] || echo "${value}"
	return ${ret}
} 2> /dev/null

# foreach_comma words [words [...]]
#
# Ouput the words given as arguments that are separated by spaces and commas
# to stdout, one per line.

foreach_comma() {
	local word
	local IFS="${IFS},"
	for word in ${@}
	do
		echo "${word}"
	done
}

# convert_mask mask
#
# Convert any mask in hex string

convert_mask() {
	if [ -z "${1}" ] ; then
		echo "0x0"
	else
		case "${1}" in
		'0x'[0-9a-fA-F]*)
			# Mask is already an hex string, just return it
			echo ${1}
			;;
		*)
			# It is a core list
			local element
			local -a array=()
			local -a coremask=()
			# Build a coremask array with non null value for each core in mask
			read -a array <<< $(IFS=',' ; echo ${1})
			for element in ${array[@]} ; do
				read min max <<< $(IFS='-' ; echo ${element})
				[ -z "$min" ] && min=0
				[ -z "$max" ] && max=${min}
				for (( core=${min}; core<=${max}; core++ )); do
					coremask[${core}]=1
				done
			done
			# Build an hex string using coremask array
			local index=0
			local res=""
			while [ ${#coremask[@]} -ne 0 ] ; do
				val=$((${coremask[${index}]:-0} + ${coremask[${index}+1]:-0}*2 + ${coremask[${index}+2]:-0}*4 + ${coremask[${index}+3]:-0}*8))
				val=`printf "%x" ${val}`
				res=${val}${res}
				unset coremask[$index]
				unset coremask[$index+1]
				unset coremask[$index+2]
				unset coremask[$index+3]
				index=$((${index}+4))
			done
			echo "0x"${res:-0}
			;;
		esac
	fi
}

# merge_mask mask1 mask2
#
# merge two masks, output in bit string (0xnnn)

merge_mask() {
	if [ -z "${1}" ] ; then 
		echo "0x0"
	elif [ -z "${2}" ] ; then
		echo `convert_mask ${1}`
	else
		local res=""
		local mask1=`convert_mask ${1}`
		local mask2=`convert_mask ${2}`
		mask1=${mask1#0x}
		mask2=${mask2#0x}
		# Move shortest string in mask1
		if [ ${#mask1} -gt ${#mask2} ] ; then
			local mask3=${mask1}
			mask1=${mask2}
			mask2=${mask3}
		fi
		# Build merged mask
		local offset=$((${#mask2}-${#mask1}))
		for (( i=${#mask1}-1; i>=0; i-- )); do
			val=$((0x${mask1:$i:1} | 0x${mask2:$i+$offset:1}))
			val=`printf "%x" ${val}`
			res=${val}${res}
		done
		for (( i=${offset}-1; i>=0; i-- )); do
			res=${mask2:$i:1}${res}
		done
		echo "0x"${res:-0}
	fi
}
