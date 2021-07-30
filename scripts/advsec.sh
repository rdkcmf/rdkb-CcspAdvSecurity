#!/bin/bash
##########################################################################
#
# Copyright 2018 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# SPDX-License-Identifier: Apache-2.0
##########################################################################
source /etc/device.properties
source /etc/log_timestamp.sh

export RUNTIME_DIR="/usr"
if [ "$DEVICE_MODEL" = "TCHXB3" ]; then
    export RUNTIME_DIR="/tmp/cujo_dnld/usr"
fi

export APPLIANCE_MODE="EMBEDDED"
export NFLUA_MODULE_PATH="/lib/modules/$(uname -r)/nflua.ko"
export LUACONNTRACK_MODULE_PATH="/lib/modules/$(uname -r)/luaconntrack.ko"
export LUADATA_MODULE_PATH="/lib/modules/$(uname -r)/luadata.ko"
export LUABASE64_MODULE_PATH="/lib/modules/$(uname -r)/luabase64.ko"
export LUAJSON_MODULE_PATH="/lib/modules/$(uname -r)/luajson.ko"
export LUNATIK_MODULE_PATH="/lib/modules/$(uname -r)/lunatik.ko"
export LUAPUMA_MODULE_PATH="/lib/modules/$(uname -r)/luapuma.ko"

export RW_DIR="/tmp"
export INFO_DIR="${RW_DIR}/advsec"
export CONFIG_DIR="${INFO_DIR}/config"
export ADVSEC_CONFIG_PARAMS_PATH="/tmp/advsec_config_params"

export DAEMONS_HIBERNATING=/tmp/advsec_daemons_hibernating
export SOFTFLOWD_ENABLE=/tmp/advsec_softflowd_enable
export SAFEBRO_ENABLE=/tmp/advsec_safebro_enable
export AGENT_HIBERNATION_PRINT=ADVSEC_AGENT_HIBERNATION_STATUS:
export ADV_PARENTAL_CONTROL_NUMBER_OF_ACTIVE_MACS_PRINT=ADV_PARENTAL_CONTROL_NUMBER_OF_ACTIVE_MACS:
export ADVSEC_INITIALIZING=/tmp/advsec_initializing
export ADVSEC_INITIALIZED=/tmp/advsec_initialized
export ADVSEC_AGENT_SHUTDOWN=/tmp/advsec_agent_shutdown
export ADVSEC_DF_ENABLED_PATH=/tmp/advsec_df_enabled
export ADV_PARENTAL_CONTROL_PATH=/tmp/adv_parental_control
export PRIVACY_PROTECTION_PATH=/tmp/adv_privacy_protection
export ADVSEC_APPBLOCK_PATH=/tmp/advsec_appblocker_enabled
export ADVSEC_AGENT_LOG_PATH=/rdklogs/logs/agent.txt
export ADVSEC_LOOKUP_EXCEED_COUNT_FILE="/tmp/advsec_lkup_exceed_cnt"
export ADVSEC_NFLUA_LOADED=/tmp/advsec_nflua_loaded
export ADVSEC_CLOUD_IP=/tmp/advsec_cloud_ipv4
export ADVSEC_CLOUD_HOST=/tmp/advsec_cloud_host
export ADVSEC_ASSOC_SUCCESS=/tmp/advsec_assoc_success
export ADVSEC_IPSETLIST_CREATED=/tmp/advsec_ipsetlist_created
export ADVSEC_DEVICE_CERT=/tmp/device.pem
export ADV_PARENTAL_CONTROL_ACTIVEMACSFILE=/tmp/activemacs.json
if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
export ADVSEC_DF_ICMPv6_ENABLED_PATH=/tmp/advsec_df_icmpv6_enabled
fi
export ADVSEC_WS_DISCOVERY_ENABLED_PATH=/tmp/advsec_ws_discovery_enabled

export DF_ENABLED=`syscfg get Advsecurity_DeviceFingerPrint`
export ADVSEC_SB_ENABLED=`syscfg get Advsecurity_SafeBrowsing`
export ADVSEC_SF_ENABLED=`syscfg get Advsecurity_Softflowd`
export ADV_PC_ENABLED=`syscfg get Adv_PCActivate`
export PRIVACY_PROTECTION_ENABLED=`syscfg get Adv_PPActivate`
export NON_ROOT_SUPPORT=`syscfg get NonRootSupport`
export ADV_PC_RFC_ENABLED=`syscfg get Adv_PCRFCEnable`
export PRIVACY_PROTECTION_RFC_ENABLED=`syscfg get Adv_PrivProtRFCEnable`
if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
export DF_ICMPv6_RFC_ENABLED=`syscfg get Adv_DFICMPv6RFCEnable`
export ADVSEC_OTM_RFC_ENABLED=`syscfg get Adv_AdvSecOTMRFCEnable`
fi
export ADVSEC_WS_DISCOVERY_RFC_ENABLED=`syscfg get Adv_WSDisAnaRFCEnable`

export ADV_PARENTAL_CONTROL_ACTIVATED_LOG=ADVANCED_PARENTAL_CONTROL_ACTIVATED
export ADV_PARENTAL_CONTROL_DEACTIVATED_LOG=ADVANCED_PARENTAL_CONTROL_DEACTIVATED
export PRIVACY_PROTECTION_ACTIVATED_LOG=PRIVACY_PROTECTION_ACTIVATED
export PRIVACY_PROTECTION_DEACTIVATED_LOG=PRIVACY_PROTECTION_DEACTIVATED
export PRIVACY_PROTECTION_RFC_ENABLED_LOG=PRIVACY_PROTECTION_RFC_STATUS_ENABLED
export PRIVACY_PROTECTION_RFC_DISABLED_LOG=PRIVACY_PROTECTION_RFC_STATUS_DISABLED
export RABID_RUNNING_AS_NON_ROOT_LOG=RABID_RUNNING_AS_NON_ROOT
export RABID_RUNNING_AS_ROOT_LOG=RABID_RUNNING_AS_ROOT
if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
export DF_ICMPv6_RFC_ENABLED_LOG=DeviceFingerPrintICMPv6.Enabled
export DF_ICMPv6_RFC_DISABLED_LOG=DeviceFingerPrintICMPv6.Disabled
export ADV_OTM_RFC_ENABLE_LOG=ADVANCE_SECURITY_OTM_ENABLED
export ADV_OTM_RFC_DISABLE_LOG=ADVANCE_SECURITY_OTM_DISABLED
fi
export ADV_WS_DISCOVERY_RFC_ENABLE_LOG=ADVANCE_SECURITY_WS_DISCOVERY_ENABLED
export ADV_WS_DISCOVERY_RFC_DISABLE_LOG=ADVANCE_SECURITY_WS_DISCOVERY_DISABLED

export ADVSEC_SAFEBRO_SETTING="${RW_DIR}/safebro.json"

export CC_BOX_TYPE=$BOX_TYPE

if [ "$MODEL_NUM" = "TG1682G" ] || [ "$MODEL_NUM" = "DPC3941" ] || [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
    export CC_PLATFORM_TYPE="PUMA"
fi

advsec_is_rabid_installed()
{
    if [ -e ${RUNTIME_DIR}/bin/launch-rabid ]; then
        echo "YES"
    else
        echo "NO"
    fi
}

advsec_start_rabid()
{
    ADV_RABID_PID=`advsec_is_alive rabid`
    if [ "$ADV_RABID_PID" = "" ] ; then
        echo_t "Starting Rabid..."
        echo_t "[ADVSEC_LOG_START]" >> $ADVSEC_AGENT_LOG_PATH
        ${RUNTIME_DIR}/bin/launch-rabid start 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    else
        echo_t 'Rabid is already running...'
    fi
}

advsec_wait_for_rabid()
{
    if [ "$1" != "" ]; then
        TIMEOUT=$1
    else
        TIMEOUT=60
    fi
    sleep $TIMEOUT
    ${RUNTIME_DIR}/bin/rabidsh -e "return"
    EXIT_STATUS=$?
    RETRY_CNT=5
    while [ ${EXIT_STATUS} -ne 0 ] && [ ${RETRY_CNT} -gt 0 ]; do
        echo_t "Rabid is not active...keep waiting...iteration=$RETRY_CNT"
        sleep 5s
        ${RUNTIME_DIR}/bin/rabidsh -e "return"
        EXIT_STATUS=$?
        RETRY_CNT=$(expr $RETRY_CNT - 1)
    done
}

advsec_rabid_start_fp()
{
    ${RUNTIME_DIR}/bin/rabid-feature on "fingerprint" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${ADVSEC_DF_ENABLED_PATH}
}

advsec_rabid_start_sb()
{
    ${RUNTIME_DIR}/bin/rabid-feature on "safebro.reputation" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${SAFEBRO_ENABLE}
}

advsec_rabid_start_sf()
{
    ${RUNTIME_DIR}/bin/rabid-feature on "tcptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${SOFTFLOWD_ENABLE}
    if [ ! -e ${ADVSEC_APPBLOCK_PATH} ]; then
        start_iot_blocker
    fi
}

advsec_stop_rabid()
{
    ${RUNTIME_DIR}/bin/launch-rabid stop 2>&1 >> $ADVSEC_AGENT_LOG_PATH
}

advsec_rabid_stop_fp()
{
    if [ -e ${ADVSEC_DF_ENABLED_PATH} ]; then
        ${RUNTIME_DIR}/bin/rabid-feature off "fingerprint" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${ADVSEC_DF_ENABLED_PATH}
    fi
}

advsec_rabid_stop_sb()
{
    if [ -e ${SAFEBRO_ENABLE} ]; then
        ${RUNTIME_DIR}/bin/rabid-feature off "safebro.reputation" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${SAFEBRO_ENABLE}
    fi
}

advsec_rabid_stop_sf()
{
    if [ -e ${SOFTFLOWD_ENABLE} ]; then
        ${RUNTIME_DIR}/bin/rabid-feature off "tcptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${SOFTFLOWD_ENABLE}
        if [ ! -e ${ADVSEC_APPBLOCK_PATH} ]; then
            stop_iot_blocker
        fi
    fi
}

start_adv_parental_control()
{
    if [ "$MODEL_NUM" = "TG1682G" ] || [ "$MODEL_NUM" = "DPC3941" ] || [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
        sysctl -w net.netfilter.nf_conntrack_acct=1
    fi

    ${RUNTIME_DIR}/bin/rabid-feature on "apptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${ADV_PARENTAL_CONTROL_PATH}
}

stop_adv_parental_control()
{
    if [ "$MODEL_NUM" = "TG1682G" ] || [ "$MODEL_NUM" = "DPC3941" ] || [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
        sysctl -w net.netfilter.nf_conntrack_acct=0
    fi
    if [ -e ${ADV_PARENTAL_CONTROL_PATH} ];then
        ${RUNTIME_DIR}/bin/rabid-feature off "apptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${ADV_PARENTAL_CONTROL_PATH}
    fi
}

start_privacy_protection()
{
    ${RUNTIME_DIR}/bin/rabid-feature on "safebro.trackerblock" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${PRIVACY_PROTECTION_PATH}
}

stop_privacy_protection()
{
    if [ -e ${PRIVACY_PROTECTION_PATH} ];then
        ${RUNTIME_DIR}/bin/rabid-feature off "safebro.trackerblock" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${PRIVACY_PROTECTION_PATH}
    fi
}

start_app_blocker()
{
    ${RUNTIME_DIR}/bin/rabid-feature on "appblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${ADVSEC_APPBLOCK_PATH}
    if [ ! -e ${SOFTFLOWD_ENABLE} ]; then
        start_iot_blocker
    fi
}

stop_app_blocker()
{
    if [ -e ${ADVSEC_APPBLOCK_PATH} ]; then
        ${RUNTIME_DIR}/bin/rabid-feature off "appblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${ADVSEC_APPBLOCK_PATH}
        if [ ! -e ${SOFTFLOWD_ENABLE} ]; then
            stop_iot_blocker
        fi
    fi
}

start_iot_blocker()
{
    ${RUNTIME_DIR}/bin/rabid-feature on "iotblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
}

stop_iot_blocker()
{
    ${RUNTIME_DIR}/bin/rabid-feature off "iotblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
}

advsec_module_load()
{
	sysfs_mount="0"
	if [ "$MODEL_NUM" = "TG1682G" ]; then
		mount -t sysfs none /sys -n
		if [ "$?" = "0" ]; then
			sysfs_mount="1"
		fi
	fi

	advsec_kernel_module_load $LUNATIK_MODULE_PATH 
	advsec_kernel_module_load $LUADATA_MODULE_PATH 
	advsec_kernel_module_load $LUAJSON_MODULE_PATH 
	advsec_kernel_module_load $LUABASE64_MODULE_PATH 
	advsec_kernel_module_load $LUACONNTRACK_MODULE_PATH
	advsec_kernel_module_load $NFLUA_MODULE_PATH
	advsec_kernel_module_load $LUAPUMA_MODULE_PATH

	if [ "$MODEL_NUM" = "TG1682G" ] && [ "$sysfs_mount" = "1" ]; then
		umount /sys
	fi

	touch ${ADVSEC_NFLUA_LOADED}
}

advsec_module_unload()
{
	rm -f ${ADVSEC_NFLUA_LOADED}
        sysfs_mount="0"
        if [ "$MODEL_NUM" = "TG1682G" ]; then
                mount -t sysfs none /sys -n
                if [ "$?" = "0" ]; then
                        sysfs_mount="1"
                fi
        fi

        advsec_kernel_module_unload $NFLUA_MODULE_PATH
        advsec_kernel_module_unload $LUAPUMA_MODULE_PATH
        advsec_kernel_module_unload $LUACONNTRACK_MODULE_PATH
        advsec_kernel_module_unload $LUAJSON_MODULE_PATH
        advsec_kernel_module_unload $LUABASE64_MODULE_PATH
        advsec_kernel_module_unload $LUADATA_MODULE_PATH
        advsec_kernel_module_unload $LUNATIK_MODULE_PATH

	if [ "$MODEL_NUM" = "TG1682G" ] && [ "$sysfs_mount" = "1" ]; then
		umount /sys
	fi
}

advsec_kernel_module_load()
{
    if [ -e $1 ]; then
        insmod $1 2>> $ADVSEC_AGENT_LOG_PATH
        STATUS=$?
        if [ ${STATUS} ]; then
            echo_t "[ADVSEC] NFLua kernel module $1 successfully loaded"  >> $ADVSEC_AGENT_LOG_PATH
        else
            echo_t "[ADVSEC] Unable to load $1 kernel module"  >> $ADVSEC_AGENT_LOG_PATH
        fi
    fi
}

advsec_kernel_module_unload()
{
    if [ -e $1 ]; then
        rmmod $1 2>> $ADVSEC_AGENT_LOG_PATH
        STATUS=$?
        if [ ${STATUS} ]; then
            echo_t "[ADVSEC] kernel module $1 successfully unloaded"  >> $ADVSEC_AGENT_LOG_PATH
        else
            echo_t "[ADVSEC] Unable to unload $1 kernel module"  >> $ADVSEC_AGENT_LOG_PATH
        fi
    fi
}

advsec_initialize_nfq_ct()
{
    if [ "$MODEL_NUM" = "PX5001" ]; then
            echo_t "Initializing nfq_ct data ..."  >> $ADVSEC_AGENT_LOG_PATH
            conntrack -L >& /dev/null
    fi
}

advsec_rabid_create_ipsets()
{
    ipset create cujo_fingerprint hash:mac -exist
    ipset create cujo_iotblock_mac hash:mac -exist
    ipset create cujo_iotblock_ip4 hash:ip family inet -exist
    ipset create cujo_iotblock_ip6 hash:ip family inet6 -exist

    touch ${ADVSEC_IPSETLIST_CREATED}
}

advsec_rabid_flush_ipsets()
{
    ipset flush
    ipset destroy cujo_fingerprint
    ipset destroy cujo_iotblock_mac
    ipset destroy cujo_iotblock_ip4
    ipset destroy cujo_iotblock_ip6
    rm -f ${ADVSEC_IPSETLIST_CREATED}
}

advsec_rabid_chain_cleanup()
{
    if ((iptables -L ${INPUT_CHAIN} &&
         iptables -L ${OUTPUT_CHAIN}
         iptables -L ${FORWARD_CHAIN})>& /dev/null); then
        echo_t "ipv4 Chain exists"
        IPTABLES="iptables"
    fi

    if ((ip6tables -L ${INPUT_CHAIN} &&
         ip6tables -L ${OUTPUT_CHAIN}
         ip6tables -L ${FORWARD_CHAIN})>& /dev/null); then
        echo_t "ipv6 Chain exists"
        IPTABLES="$IPTABLES ip6tables"
    fi

    if [ "${IPTABLES}" != "" ]; then
        for ipt in ${IPTABLES}; do
            chains=`${ipt} -w -S | grep -- "^-N ${CHAIN_PREFIX}" | cut -f2 -d' '`

            echo "$chains" | while read -r chain; do
                    ${ipt} -w -F ${chain}
            done

            echo "$chains" | while read -r chain; do
                    if ! echo -- "${ENTRY_CHAINS}" | grep -wq -- "${chain}"; then
                            ${ipt} -w -X ${chain}
                    fi
            done

            ${ipt} -D INPUT -j CUJO_INPUT
            ${ipt} -D OUTPUT -j CUJO_OUTPUT
            ${ipt} -D FORWARD -j CUJO_FORWARD
            ${ipt} -w -X CUJO_FORWARD
            ${ipt} -w -X CUJO_INPUT
            ${ipt} -w -X CUJO_OUTPUT
        done
    fi
    
    ipset list -name | grep -- "^${SET_PREFIX}" | while read -r set; do
        ipset destroy ${set}
    done
    trap - EXIT
}

advsec_rabid_restart_needed()
{
	result="0"
	#Check for cloud socket connection
	if [ -e ${SOFTFLOWD_ENABLE} ] || [ -e ${ADV_PARENTAL_CONTROL_PATH} ]; then
		if [ -e ${ADVSEC_CLOUD_IP} ] && [ -e ${ADVSEC_ASSOC_SUCCESS} ]; then
			ip_port=`cat ${ADVSEC_CLOUD_IP}`
			if [ "${ip_port}" != "" ]; then
				stat=`sysevent get wan-status`
				if [ "${stat}" = "started" ]; then
					res=`netstat -an | grep ${ip_port} | grep "ESTABLISHED"`
					if [ "${res}" = "" ]; then
						result="1"
						touch ${ADVSEC_AGENT_SHUTDOWN}
						echo_t "[ADVSEC] Rabid is going to restart due to no websocket connection..." >> ${ADVSEC_AGENT_LOG_PATH}
						echo_t "netstat output: $res" >> ${ADVSEC_AGENT_LOG_PATH}
						echo_t "IP_PORT: $ip_port" >> ${ADVSEC_AGENT_LOG_PATH}
					fi
				fi
			fi
		fi
	fi
	echo ${result}
}

advsec_is_alive() {

	if [ "$1" = "rabid" ]
	then
		PROCESS_PID=`pidof "rabid"`
	fi
	echo $PROCESS_PID
}

advsec_stop_process() {
	ADVSEC_RDK_LOG_FILE=""
	echo_t "Stopping process " $1
	if [ "$1" = "rabid" ]
	then
		PROCESS_PID=`pidof "rabid"`
		ADVSEC_RDK_LOG_FILE=$ADVSEC_AGENT_LOG_PATH
	fi
	if [ "$PROCESS_PID" != "" ]; then
		kill -TERM $PROCESS_PID
	fi
	if [ "$ADVSEC_RDK_LOG_FILE" != "" ]; then
		echo_t "[ADVSEC_LOG_STOP]" >> $ADVSEC_RDK_LOG_FILE
	fi
}

advsec_cleanup_config() {
	rm -rf $INFO_DIR

        if [ -e ${ADVSEC_SAFEBRO_SETTING} ]; then
                rm -rf ${ADVSEC_SAFEBRO_SETTING}
        fi

        if [ -e ${ADVSEC_CLOUD_IP} ]; then
                rm -rf ${ADVSEC_CLOUD_IP}
        fi
}

advsec_cleanup_config_rabid() {
        if [ -e $DAEMONS_HIBERNATING ]; then
                rm -f $DAEMONS_HIBERNATING
        fi

        if [ -e ${ADVSEC_ASSOC_SUCCESS} ]; then
                rm -f ${ADVSEC_ASSOC_SUCCESS}
        fi

	if [ -e ${ADVSEC_SAFEBRO_SETTING} ]; then
		rm ${ADVSEC_SAFEBRO_SETTING}
	fi

        if [ -e ${ADV_PARENTAL_CONTROL_ACTIVEMACSFILE} ]; then
                rm ${ADV_PARENTAL_CONTROL_ACTIVEMACSFILE}
        fi

	if [ -e ${ADVSEC_CLOUD_IP} ]; then
		rm ${ADVSEC_CLOUD_IP}
	fi

	if [ -e ${ADVSEC_CLOUD_HOST} ]; then
		rm ${ADVSEC_CLOUD_HOST}
	fi

	if [ -e ${ADVSEC_DEVICE_CERT} ]; then
		rm ${ADVSEC_DEVICE_CERT}
	fi

        advsec_cleanup_config
}

advsec_restart_rabid() {
    if [ ! -f $ADVSEC_INITIALIZING ]; then
        touch $ADVSEC_INITIALIZING
        if [ "$1" != "" ]; then
            echo_t "[ADVSEC] Restarting Rabid due to $1..." >> ${ADVSEC_AGENT_LOG_PATH}
        else
            echo_t "[ADVSEC] Restarting Rabid due to Selfheal..." >> ${ADVSEC_AGENT_LOG_PATH}
        fi

        advsec_stop_rabid

        advsec_cleanup_config_rabid

        sleep 5
        if [ ! -e ${ADVSEC_NFLUA_LOADED} ]
        then
                advsec_module_load
        fi

        if [ ! -e ${ADVSEC_IPSETLIST_CREATED} ]
        then
                advsec_rabid_create_ipsets
        fi

        advsec_start_rabid
        advsec_wait_for_rabid 30

        if [ -e ${ADVSEC_DF_ENABLED_PATH} ]
        then
                advsec_rabid_start_fp
        fi

        if [ -e ${SAFEBRO_ENABLE} ]
        then
                advsec_rabid_start_sb
        fi
        if [ -e ${SOFTFLOWD_ENABLE} ]
        then
                advsec_rabid_start_sf
        fi

        if [ -e ${ADV_PARENTAL_CONTROL_PATH} ] && [ "$ADV_PC_RFC_ENABLED" = "1" ]
        then
               start_adv_parental_control
        fi

        if [ -e ${PRIVACY_PROTECTION_PATH} ] && [ "$PRIVACY_PROTECTION_RFC_ENABLED" = "1" ]
        then
               start_privacy_protection
        fi

        rm $ADVSEC_INITIALIZING
    fi
}

advsec_get_rabid_group_name() {
        rabiduser=`ps | grep -i rabid | grep -v grep | head -n 1 | awk '{print $2}'`
        echo $rabiduser
}

wait_for_lanip()
{
    ip_retry_limit=6
    while [ ${ip_retry_limit} -gt 0 ]; do
        lanipv6addr=`ip -6 a s brlan0 | grep global | cut -d " " -f 6`
        lanipv4addr=`ip -4 a s brlan0 | grep global | cut -d " " -f 6`
        if [ "$lanipv6addr" = "" ] || [ "$lanipv4addr" = "" ]; then
             echo_t "Waiting for LAN ipv6 and ipv4 address..." >> ${ADVSEC_AGENT_LOG_PATH}
             sleep 10
             ip_retry_limit=$(expr $ip_retry_limit - 1)
        else
             echo_t "LAN IPv6 Address: $lanipv6addr and IPv4 Address: $lanipv4addr" >> ${ADVSEC_AGENT_LOG_PATH}
             break
        fi
    done
}

