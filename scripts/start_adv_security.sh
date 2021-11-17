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
source $(dirname $(realpath ${0}))/advsec.sh

source /etc/utopia/service.d/log_capture_path.sh

export RUNTIME_BIN_DIR="$(dirname $(realpath ${0}))"

start_device_services()
{

if [ "$1" = "-enable" ]
then


    bridge_mode=`syscfg get bridge_mode`
    if [ "$bridge_mode" = "2" ]; then
        echo_t "Advanced Security : Device is in Bridge Mode, do not launch agent!" >> ${ADVSEC_AGENT_LOG_PATH}
        exit 0
    fi

    if [ "x$(advsec_is_agent_installed)" == "xYES" ]; then
        echo_t "Advanced Security : ${CUJO_AGENT_LOG} is installed on the device" >> ${ADVSEC_AGENT_LOG_PATH}
    else
        echo_t "Advanced Security : ${CUJO_AGENT_LOG} is not installed on the device..." >> ${ADVSEC_AGENT_LOG_PATH}
        exit 0
    fi

    if [ -f $ADVSEC_INITIALIZING ]; then
        echo_t "Advanced Security Service is already being initialized" >> ${ADVSEC_AGENT_LOG_PATH}
        exit 0
    fi

    touch $ADVSEC_INITIALIZING

    if [ -f $DAEMONS_HIBERNATING ]; then
        rm $DAEMONS_HIBERNATING
    fi

    wait_for_lanip

    start_agent_services

    touch $ADVSEC_INITIALIZED

    if [ "$DF_ENABLED" = "1" ]; then
        echo_t "Device_Finger_Printing_enabled:true"
    fi

    if [ "$ADVSEC_SB_ENABLED" = "1" ]
    then
        start_advsec_safe_browsing
    else
        echo_t "ADV_SECURITY_SAFE_BROWSING_DISABLE"
    fi
    if [ "$ADVSEC_SF_ENABLED" = "1" ]
    then
        start_advsec_softflowd
    else
        echo_t "ADV_SECURITY_SOFTFLOWD_DISABLE"
    fi

    if [ "$ADV_PC_ENABLED" = "1" ] && [ "$ADV_PC_RFC_ENABLED" = "1" ]; then
        advanced_parental_control_setup "-startAdvPC"
    fi

    if [ "$PRIVACY_PROTECTION_ENABLED" = "1" ] && [ "$PRIVACY_PROTECTION_RFC_ENABLED" = "1" ]; then
        privacy_protection_setup "-startPrivProt"
    fi

    if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
        if [ "$DF_ICMPv6_RFC_ENABLED" = "1" ]; then
            enable_icmpv6
        else
            disable_icmpv6
        fi
    fi

    if [ "$ADVSEC_WS_DISCOVERY_RFC_ENABLED" = "1" ]; then
            enable_wsdiscovery
    else
            disable_wsdiscovery
    fi

    if [ "$ADVSEC_OTM_RFC_ENABLED" = "1" ]; then
            enable_otm
    else
            disable_otm
    fi

    rm $ADVSEC_INITIALIZING

    echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
    sysevent set firewall-restart

    if [ "$ADV_PC_ENABLED" = "1" ] && [ ! -e ${ADV_PARENTAL_CONTROL_RFC_DISABLED_PATH} ]; then
            #This is a workaround for an issue in firewall utility, where cujo related rules are not added.
            #To be removed once firewall utility issue is fixed!
            sleep 20s
            ipt4=`cat /tmp/.ipt | grep CUJO | wc -l`
            ipt6=`cat /tmp/.ipt_v6 | grep CUJO | wc -l`
            ip4=`iptables-save | grep CUJO | wc -l`
            ip6=`ip6tables-save | grep CUJO | wc -l`
            if [ ${ipt4} != ${ip4} ] || [ ${ipt6} != ${ip6} ]; then
		 echo_t "${CUJO_AGENT_LOG} triggering firewall restart to reload rules" >> ${ADVSEC_AGENT_LOG_PATH}
           	 sysevent set firewall-restart
            else
		 echo_t "Rules are loaded correctly" >> ${ADVSEC_AGENT_LOG_PATH}
            fi
    fi

    AGENT_USER=`advsec_get_agent_group_name`
    if [ "${AGENT_USER}" = "root" ]; then
        echo_t ${AGENT_RUNNING_AS_ROOT_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    elif [ "${AGENT_USER}" = "${CUJO_AGENT_USER_NAME}" ]; then
        echo_t ${AGENT_RUNNING_AS_NON_ROOT_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    fi

    exit 0
elif [ "$1" = "-disable" ]
then
    stop_agent_services

    if [ "$DF_ENABLED" != "1" ]; then
        echo_t "Device_Finger_Printing_enabled:false"
    fi

    if [ -f $ADVSEC_INITIALIZED ]; then
        rm $ADVSEC_INITIALIZED
    fi

    if [ -f $ADVSEC_INITIALIZING ]; then
        rm $ADVSEC_INITIALIZING
    fi

    if [ -f $SOFTFLOWD_ENABLE ]; then
        rm $SOFTFLOWD_ENABLE
    fi

    if [ -f $SAFEBRO_ENABLE ]; then
        rm $SAFEBRO_ENABLE
    fi

    if [ -f $ADVSEC_AGENT_SHUTDOWN ]; then
        rm $ADVSEC_AGENT_SHUTDOWN
    fi

    if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
        if [ -f $ADVSEC_DF_ICMPv6_ENABLED_PATH ]; then
            rm $ADVSEC_DF_ICMPv6_ENABLED_PATH
        fi
    fi

    if [ -f $ADVSEC_WS_DISCOVERY_ENABLED_PATH ]; then
        rm $ADVSEC_WS_DISCOVERY_ENABLED_PATH
    fi

    exit 0
fi
}

start_agent_services()
{
    advsec_module_load
    advsec_agent_create_ipsets
    advsec_start_agent
    advsec_wait_for_agent

    if [ "$DF_ENABLED" = "1" ]; then
        advsec_agent_start_fp
    fi

    advsec_initialize_nfq_ct
}

stop_agent_services()
{
    rm -f ${ADVSEC_NFLUA_LOADED}
    stop_privacy_protection
    stop_adv_parental_control
    advsec_agent_stop_sf
    advsec_agent_stop_sb
    advsec_agent_stop_fp
    advsec_stop_agent
    advsec_agent_flush_ipsets
    RETRY_CNT=5
    while [ ${RETRY_CNT} -gt 0 ]; do
        RETRY_CNT=$(expr $RETRY_CNT - 1)
        echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
        sysevent set firewall-restart
        sleep 10s
        ip4=`iptables-save | grep CUJO | wc -l`
        ip6=`ip6tables-save | grep CUJO | wc -l`
        if [ $ip4 = "0" ] && [ $ip6 = "0" ]; then
            break
        else
            echo_t "${CUJO_AGENT_LOG} rules are not removed yet! ip4 = $ip4 And ip6 = $ip6 ..Retry again" >> ${ADVSEC_AGENT_LOG_PATH}
            sleep 60s
        fi
    done
    advsec_module_unload
    advsec_cleanup_config_agent
}

start_advsec_safe_browsing()
{
    advsec_agent_start_sb
    echo_t "ADV_SECURITY_SAFE_BROWSING_ENABLE"
}

stop_advsec_safe_browsing()
{
    advsec_agent_stop_sb
    echo_t "ADV_SECURITY_SAFE_BROWSING_DISABLE"
    if [ -e ${ADVSEC_LOOKUP_EXCEED_COUNT_FILE} ]; then
        rm ${ADVSEC_LOOKUP_EXCEED_COUNT_FILE}
    fi
}

start_advsec_softflowd()
{
    advsec_agent_start_sf
    echo_t "ADV_SECURITY_SOFTFLOWD_ENABLE"
}

stop_advsec_softflowd()
{
    advsec_agent_stop_sf
    echo_t "ADV_SECURITY_SOFTFLOWD_DISABLE"
}

start_advanced_security()
{
    if [ "$1" = "-start" ]
    then
            if [ "$2" = "sb" ]
            then
                start_advsec_safe_browsing
            fi
            if [ "$3" = "sf" ]
            then
                start_advsec_softflowd
            fi
    fi

    if [ "$1" = "-stop" ]
    then
            if [ "$2" = "sb" ]
            then
                stop_advsec_safe_browsing
            fi
            if [ "$3" = "sf" ]
            then
                stop_advsec_softflowd
            fi
    fi
}

advanced_parental_control_setup()
{
    if [ "$1" = "-startAdvPC" ]
    then
        start_adv_parental_control
        echo_t ${ADV_PARENTAL_CONTROL_ACTIVATED_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    fi

    if [ "$1" = "-stopAdvPC" ]
    then
        stop_adv_parental_control
        echo_t ${ADV_PARENTAL_CONTROL_DEACTIVATED_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    fi
}

privacy_protection_setup()
{
    if [ "$1" = "-startPrivProt" ]
    then
        start_privacy_protection
        echo_t ${PRIVACY_PROTECTION_ACTIVATED_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    fi

    if [ "$1" = "-stopPrivProt" ]
    then
        stop_privacy_protection
        echo_t ${PRIVACY_PROTECTION_DEACTIVATED_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    fi
}

enable_icmpv6()
{
    touch $ADVSEC_DF_ICMPv6_ENABLED_PATH
    echo_t ${DF_ICMPv6_RFC_ENABLED_LOG} >> ${ADVSEC_AGENT_LOG_PATH}

    if [ "$1" = "FR" ]; then
        echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
        sysevent set firewall-restart
    fi
}

disable_icmpv6()
{
    rm -f $ADVSEC_DF_ICMPv6_ENABLED_PATH
    echo_t ${DF_ICMPv6_RFC_DISABLED_LOG} >> ${ADVSEC_AGENT_LOG_PATH}

    if [ "$1" = "FR" ]; then
        echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
        sysevent set firewall-restart
    fi
}

enable_wsdiscovery()
{
    touch $ADVSEC_WS_DISCOVERY_ENABLED_PATH
    echo_t ${ADV_WS_DISCOVERY_RFC_ENABLE_LOG} >> ${ADVSEC_AGENT_LOG_PATH}

    if [ "$1" = "FR" ]; then
        echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
        sysevent set firewall-restart
    fi
}

disable_wsdiscovery()
{
    rm -f $ADVSEC_WS_DISCOVERY_ENABLED_PATH
    echo_t ${ADV_WS_DISCOVERY_RFC_DISABLE_LOG} >> ${ADVSEC_AGENT_LOG_PATH}

    if [ "$1" = "FR" ]; then
        echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
        sysevent set firewall-restart
    fi
}

enable_otm()
{
   echo_t ${ADV_OTM_RFC_ENABLE_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
   if [ "$1" = "RR" ]; then
       advsec_restart_agent "OTM_RFC_Enabled"
   fi
}

disable_otm()
{
   echo_t ${ADV_OTM_RFC_DISABLE_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
   if [ "$1" = "RR" ]; then
       advsec_restart_agent "OTM_RFC_Disabled"
   fi
}

if [ "$1" = "-enable" ] || [ "$1" = "-disable" ]
then
    start_device_services $1 $2 $3
fi

if [ "$1" = "-start" ] || [ "$1" = "-stop" ]
then
    start_advanced_security $1 $2 $3
    if [ "$BOX_TYPE" == "XB3" ] || [ "$BOX_TYPE" == "XF3" ]; then
        echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
        sysevent set firewall-restart
    fi
fi

if [ "$1" = "-startAdvPC" ] || [ "$1" = "-stopAdvPC" ]
then
    if [ "$1" = "-startAdvPC" ] && [ "$ADV_PC_RFC_ENABLED" = "0" ]; then
        echo_t "${CUJO_AGENT_LOG} cannot activate AdvParentalControl feature due to RFC is disabled" >> ${ADVSEC_AGENT_LOG_PATH}
    else
        advanced_parental_control_setup $1
        if [ "$BOX_TYPE" == "XB3" ] || [ "$BOX_TYPE" == "XF3" ]; then
            echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
            sysevent set firewall-restart
        fi
    fi
fi

if [ "$1" = "-startPrivProt" ] || [ "$1" = "-stopPrivProt" ]
then
    if [ "$1" = "-startPrivProt" ] && [ "$PRIVACY_PROTECTION_RFC_ENABLED" = "0" ]; then
        echo_t "${CUJO_AGENT_LOG} cannot activate PrivacyProtection feature due to RFC is disabled" >> ${ADVSEC_AGENT_LOG_PATH}
    else
        privacy_protection_setup $1
        if [ "$BOX_TYPE" == "XB3" ] || [ "$BOX_TYPE" == "XF3" ]; then
            echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
            sysevent set firewall-restart
        fi
    fi
fi

if [ "$1" = "-configure_features" ]
then
    if [ "${ADVSEC_SB_ENABLED}" = "1" ]; then
        if [ ! -e ${SAFEBRO_ENABLE} ]; then
            start_advsec_safe_browsing
        fi
    else
        if [ -e ${SAFEBRO_ENABLE} ]; then
            stop_advsec_safe_browsing
        fi
    fi

    if [ "${ADVSEC_SF_ENABLED}" = "1" ]; then
        if [ ! -e ${SOFTFLOWD_ENABLE} ]; then
            start_advsec_softflowd
        fi
    else
        if [ -e ${SOFTFLOWD_ENABLE} ]; then
            stop_advsec_softflowd
        fi
    fi

    if [ "${ADV_PC_ENABLED}" = "1" ]; then
        if [ ! -e ${ADV_PARENTAL_CONTROL_PATH} ]; then
            if [ "$ADV_PC_RFC_ENABLED" = "0" ]; then
                echo_t "${CUJO_AGENT_LOG} cannot activate AdvParentalControl feature due to RFC is disabled" >> ${ADVSEC_AGENT_LOG_PATH}
            else
                advanced_parental_control_setup "-startAdvPC"
            fi
        fi
    else
        if [ -e ${ADV_PARENTAL_CONTROL_PATH} ]; then
            advanced_parental_control_setup "-stopAdvPC"
        fi
    fi

    if [ "${PRIVACY_PROTECTION_ENABLED}" = "1" ]; then
        if [ ! -e ${PRIVACY_PROTECTION_PATH} ]; then
            if [ "$PRIVACY_PROTECTION_RFC_ENABLED" = "0" ]; then
                 echo_t "${CUJO_AGENT_LOG} cannot activate PrivacyProtection feature due to RFC is disabled" >> ${ADVSEC_AGENT_LOG_PATH}
            else
                privacy_protection_setup "-startPrivProt"
            fi
        fi
    else
        if [ -e ${PRIVACY_PROTECTION_PATH} ]; then
            privacy_protection_setup "-stopPrivProt"
        fi
    fi

    if [ "$BOX_TYPE" == "XB3" ] || [ "$BOX_TYPE" == "XF3" ]; then
        echo_t "${CUJO_AGENT_LOG} triggering firewall restart..." >> ${ADVSEC_AGENT_LOG_PATH}
        sysevent set firewall-restart
    fi

fi

if [ "$1" = "-restart" ] && [ -e ${ADVSEC_DF_ENABLED_PATH} ]
then
    AGENT_USER=`advsec_get_agent_group_name`
    if [ "${AGENT_USER}" = "root" ] && [ "${NON_ROOT_SUPPORT}" = "true" ]
    then
        advsec_restart_agent "NonRootSupportToggle"
        echo_t ${AGENT_RUNNING_AS_NON_ROOT_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    fi
    if [ "${AGENT_USER}" = "${CUJO_AGENT_USER_NAME}" ] && [ "${NON_ROOT_SUPPORT}" = "false" ]
    then
        advsec_restart_agent "NonRootSupportToggle"
        echo_t ${AGENT_RUNNING_AS_ROOT_LOG} >> ${ADVSEC_AGENT_LOG_PATH}
    fi
fi

if [ "$1" = "-enableICMP6" ]; then
   enable_icmpv6 "FR"
fi

if [ "$1" = "-disableICMP6" ]; then
   disable_icmpv6 "FR"
fi

if [ "$1" = "-enableOTM" ]; then
    enable_otm "RR"
fi

if [ "$1" = "-disableOTM" ]; then
    disable_otm "RR"
fi

if [ "$1" = "-enableWSDiscovery" ]; then
   enable_wsdiscovery "FR"
fi

if [ "$1" = "-disableWSDiscovery" ]; then
   disable_wsdiscovery "FR"
fi

if [ "$1" = "-restartAgent" ] && [ -e ${ADVSEC_DF_ENABLED_PATH} ]
then
    advsec_restart_agent $2
fi

if [ "$1" = "-agentloglevel" ]; then
   advsec_agent_loglevel $2
fi