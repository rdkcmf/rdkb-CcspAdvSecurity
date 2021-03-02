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
ADVSEC_LOG_FORMAT=Device_Finger_Printing_enabled:true
ADVSEC_SB_FORMAT=ADV_SECURITY_SAFE_BROWSING_ENABLE
ADVSEC_SF_FORMAT=ADV_SECURITY_SOFTFLOWD_ENABLE
ADVSEC_DMZ_ENABLE=ADV_SECURITY_DMZ_ENABLED
ADVSEC_LISTEN_MODE_ENABLE=ADV_SECURITY_LISTEN_ONLY_MODE
ADVSEC_LISTEN_MODE_FORMAT="\"threshold\":0"

check_status()
{
    if [ -e $ADVSEC_DF_ENABLED_PATH ]; then
        print_telemetry_log ${ADVSEC_LOG_FORMAT} ${CONSOLEFILE}
    fi

    if [ -e $SAFEBRO_ENABLE ]; then
        print_telemetry_log ${ADVSEC_SB_FORMAT} ${CONSOLEFILE}
    fi

    if [ -e $SOFTFLOWD_ENABLE ]; then
        print_telemetry_log ${ADVSEC_SF_FORMAT} ${CONSOLEFILE}
    fi

    if [ -e ${DAEMONS_HIBERNATING} ] && [ ! -e ${SOFTFLOWD_ENABLE} ] && [ ! -e ${ADV_PARENTAL_CONTROL_PATH} ]; then
        _status=1
    else
        _status=0
    fi
    print_telemetry_log $AGENT_HIBERNATION_PRINT$_status $ADVSEC_AGENT_LOG_PATH

    _RES=`syscfg get dmz_enabled`
    if [ "$_RES" = "1" ] ; then
        print_telemetry_log ${ADVSEC_DMZ_ENABLE} ${ADVSEC_AGENT_LOG_PATH}
    fi

    if [ -e $ADVSEC_SAFEBRO_SETTING ]; then
        _RES=`grep $ADVSEC_LISTEN_MODE_FORMAT $ADVSEC_SAFEBRO_SETTING`
        if [ "$?" = "0" ] ; then
            print_telemetry_log ${ADVSEC_LISTEN_MODE_ENABLE} ${ADVSEC_AGENT_LOG_PATH}
        fi
    fi

    if [ "${ADV_PC_ENABLED}" = "1" ]; then
        print_telemetry_log ${ADV_PARENTAL_CONTROL_ACTIVATED_LOG} ${ADVSEC_AGENT_LOG_PATH}
    else
        print_telemetry_log ${ADV_PARENTAL_CONTROL_DEACTIVATED_LOG} ${ADVSEC_AGENT_LOG_PATH}
    fi

    if [ ! -e $PRIVACY_PROTECTION_RFC_DISABLED_PATH ]; then
        print_telemetry_log ${PRIVACY_PROTECTION_RFC_ENABLED_LOG} ${ADVSEC_AGENT_LOG_PATH}
        if [ "${PRIVACY_PROTECTION_ENABLED}" = "1" ]; then
            print_telemetry_log ${PRIVACY_PROTECTION_ACTIVATED_LOG} ${ADVSEC_AGENT_LOG_PATH}
        else
            print_telemetry_log ${PRIVACY_PROTECTION_DEACTIVATED_LOG} ${ADVSEC_AGENT_LOG_PATH}
        fi
    else
        print_telemetry_log ${PRIVACY_PROTECTION_RFC_DISABLED_LOG} ${ADVSEC_AGENT_LOG_PATH}
    fi

    RABID_USER=`advsec_get_rabid_group_name`
    if [ "$RABID_USER" = "root" ]; then
        print_telemetry_log ${RABID_RUNNING_AS_ROOT_LOG} ${ADVSEC_AGENT_LOG_PATH}
    elif [ "$RABID_USER" = "_rabid" ]; then
        print_telemetry_log ${RABID_RUNNING_AS_NON_ROOT_LOG} ${ADVSEC_AGENT_LOG_PATH}
    fi
    if [ -e ${ADV_PARENTAL_CONTROL_PATH} ]; then
        if [ -e $ADV_PARENTAL_CONTROL_ACTIVEMACSFILE ]; then
            _ACTIVE_MACS_COUNT=`cat $ADV_PARENTAL_CONTROL_ACTIVEMACSFILE | tr ',' '\n' | awk 'BEGIN {count=0} /([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}/ {count++} END {print count}'`
        else
            _ACTIVE_MACS_COUNT=0
        fi
        print_telemetry_log $ADV_PARENTAL_CONTROL_NUMBER_OF_ACTIVE_MACS_PRINT$_ACTIVE_MACS_COUNT ${ADVSEC_AGENT_LOG_PATH}
    fi
}

print_telemetry_log()
{
    string_=$1
    file_path=$2

    _RES=`grep ${string_} ${file_path}`
    if [ "$?" = "1" ] ; then
        echo_t ${string_} >> ${file_path}
    fi
}

$1

