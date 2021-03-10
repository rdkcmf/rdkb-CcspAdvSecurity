/*
 *
 * Copyright 2016 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * SPDX-License-Identifier: Apache-2.0
*/

/**************************************************************************

    module: cosa_adv_security_internal.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implements back-end apis for the COSA Data Model Library

**************************************************************************/

#include "cosa_adv_security_internal.h"
#include "cosa_adv_security_dml.h"
#include "cosa_adv_security_webconfig.h"
#include "ccsp_psm_helper.h"
#include <sysevent/sysevent.h>
#include <time.h>
#include "cJSON.h"
#include <ccsp/platform_hal.h>
#include <syscfg/syscfg.h>
#include "safec_lib_common.h"
#if defined(_COSA_BCM_MIPS_)
#include <ccsp/dpoe_hal.h>
#else
#include <ccsp/cm_hal.h>
#endif
#if !(_COSA_BCM_MIPS_ || _COSA_DRG_TPG_ || CONFIG_CISCO)
#include <autoconf.h>
#endif

#define ADVSEC_WAIT_FOR_TIMEOUT (60 * 60)
#define ADVSEC_SYSEVENT_PARENTAL_CONTROL_RFC_EVENT "adv_parental_control"
#define ADVSEC_SYSEVENT_PRIVACY_PROTECTION_RFC_EVENT "privacy_protection"
#define ADVSEC_SYSEVENT_RABID_NONROOT_RFC_EVENT "NonRootSupport"
#define ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT "bridge_mode"
#define ADVSEC_SYSEVENT_CLOUD_HOST_IP "advsec_host_ip"
#define MAX_VALUE 32
#define COMMAND_MAX 128
#define BUFFERSIZE_MAX  256
#define ADVSEC_LOOKUP_EXCEED_COUNT_FILE "/tmp/advsec_lkup_exceed_cnt"

#ifdef DOWNLOADMODULE_ENABLE
#define TEMP_DOWNLOAD_LOCATION "/tmp/cujo_dnld"
#else
#define TEMP_DOWNLOAD_LOCATION ""
#endif

#define ADVSEC_CONFIG_PARAMS_DIR_PATH "/tmp/advsec_config_params"
#define ADVSEC_CONFIG_PARAMS_MODEL_PATH "/tmp/advsec_config_params/MODEL"
#define ADVSEC_CONFIG_PARAMS_MNCF_PATH "/tmp/advsec_config_params/MANUFACTURER"
#define ADVSEC_CONFIG_PARAMS_FW_PATH "/tmp/advsec_config_params/FWVER"
#define ADVSEC_CONFIG_PARAMS_HW_PATH "/tmp/advsec_config_params/HWVER"
#define ADVSEC_CONFIG_PARAMS_CM_MAC_PATH "/tmp/advsec_config_params/CMMAC"
#define ADVSEC_INITIALIZED_FILE_PATH "/tmp/advsec_initialized"
#define ADVSEC_CLOUD_HOST "/tmp/advsec_cloud_host"
#define ADVSEC_CLOUD_IP "/tmp/advsec_cloud_ipv4"
#define ADVSEC_DEFAULT_CM_MAC "00:1A:2B:11:22:33"

#ifdef CONFIG_CISCO
#define CONFIG_VENDOR_NAME  "Cisco"
#endif

#if (_COSA_BCM_MIPS_ || _COSA_DRG_TPG_)
#define CONFIG_VENDOR_NAME "ARRIS Group, Inc."
#endif

#define NUM_SYSEVENT_TYPES (sizeof(advSysEvent_type_table)/sizeof(advSysEvent_type_table[0]))

extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
extern COSA_DATAMODEL_AGENT* g_pAdvSecAgent;

static char *g_DeviceFingerPrintEnabled = "Advsecurity_DeviceFingerPrint";
static char *g_AdvSecuritySBEnabled       = "Advsecurity_SafeBrowsing";
static char *g_AdvSecuritySFEnabled       = "Advsecurity_Softflowd";
static char *g_DeviceFingerPrintLogginPeriod = "Advsecurity_LoggingPeriod";
static char *g_DeviceFingerPrintEndpointURL = "Advsecurity_EndpointURL";
static char *g_AdvSecurityLookupTimeout = "Advsecurity_LookupTimeout";
static char *g_AdvParentalControl = "Adv_PCActivate";
static char *g_PrivacyProtection = "Adv_PPActivate";

static pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t logCond = PTHREAD_COND_INITIALIZER;

void advsec_handle_sysevent_async(void);
static void advsec_start_logger_thread(void);
static BOOL WaitForLoggerTimeout(ULONG period);
enum advSysEvent_e{
    SYSEVENT_PARENTAL_CONTROL_RFC_EVENT,
    SYSEVENT_PRIVACY_PROTECTION_RFC_EVENT,
    SYSEVENT_BRIDGE_MODE_EVENT,
    SYSEVENT_CLOUD_HOST_IP,
    SYSEVENT_RABID_NONROOT_RFC_EVENT,
};

/*Structure defined to get the AdvSysEvent Noti type from the given Event names */

typedef struct advSysEvent_pair{
  char                 *name;
  enum advSysEvent_e   event;
} ADV_SYSEVENT_PAIR;

ADV_SYSEVENT_PAIR advSysEvent_type_table[] = {
  { ADVSEC_SYSEVENT_PARENTAL_CONTROL_RFC_EVENT,     SYSEVENT_PARENTAL_CONTROL_RFC_EVENT   },
  { ADVSEC_SYSEVENT_PRIVACY_PROTECTION_RFC_EVENT,   SYSEVENT_PRIVACY_PROTECTION_RFC_EVENT },
  { ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT,              SYSEVENT_BRIDGE_MODE_EVENT            },
  { ADVSEC_SYSEVENT_CLOUD_HOST_IP,                  SYSEVENT_CLOUD_HOST_IP                },
  { ADVSEC_SYSEVENT_RABID_NONROOT_RFC_EVENT,        SYSEVENT_RABID_NONROOT_RFC_EVENT      }
};

int get_advSysEvent_type_from_name(char *name, enum advSysEvent_e *type_ptr)
{
  errno_t rc = -1;
  int ind = -1;
  unsigned int i = 0;
  size_t str_size = 0;

  if((name == NULL) || (type_ptr == NULL))
     return 0;

  str_size = strlen(name);

  for (i = 0 ; i < NUM_SYSEVENT_TYPES ; ++i)
  {
      rc = strcmp_s(name, str_size, advSysEvent_type_table[i].name, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
          *type_ptr = advSysEvent_type_table[i].event;
          return 1;
      }
  }
  return 0;
}

static BOOL Is_Device_Finger_Print_Enabled()
{
    return (g_pAdvSecAgent->bEnable);
}

static BOOL Is_Device_Finger_Print_Enabled_Completed()
{
    FILE *file = NULL;
    if ((file = fopen("/tmp/advsec_initialized", "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

static BOOL Is_Rabid_Initialization_Completed()
{
    FILE *file = NULL;
    if ((file = fopen(ADVSEC_INITIALIZED_FILE_PATH, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

static void advsec_create_dir(char *path)
{
    struct stat st = {0};
     int ret =0;
    if (stat(path, &st) == -1)
    {
      /* Coverity Fix CID: 135545 TOCTOU */
      ret = mkdir(path, 0777);
      if (ret < 0 && errno != EEXIST)
      CcspTraceError(("%s:%d\n", __FUNCTION__,errno));
    }
}

static BOOL advsec_write_to_file(char *fpath, char *str)
{
    FILE *file = NULL;

    if ( !fpath || !str )
    {
        return 0;
    }

    if ((file = fopen(fpath, "w")))
    {
        fprintf(file,"%s",str);
        fclose(file);
        return 1;
    }
    return 0;
}

static BOOL advsec_read_from_file(char *fpath, char *str)
{
    FILE *file = NULL;

    if ( !fpath || !str )
    {
        return 0;
    }

    if ((file = fopen(fpath, "r")))
    {
        fscanf(file,"%s",str);
        fclose(file);
        return 1;
    }
    return 0;
}

ANSC_HANDLE
CosaSecurityCreate
    (
        VOID
    )
{
	
	PCOSA_DATAMODEL_AGENT       pMyObject    = (PCOSA_DATAMODEL_AGENT)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PCOSA_DATAMODEL_AGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));

    if ( !pMyObject )
    {
    	CcspTraceError(("%s exit ERROR \n", __FUNCTION__));
        return  (ANSC_HANDLE)NULL;
    }

    pMyObject->pAdvSec = (PCOSA_DATAMODEL_ADVSEC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSEC));

    if ( !pMyObject->pAdvSec )
    {
    	CcspTraceError(("%s exit ERROR \n", __FUNCTION__));
    	AnscFreeMemory((ANSC_HANDLE)pMyObject);
        return  (ANSC_HANDLE)NULL;
    }

    pMyObject->pAdvSec->pSafeBrows = (PCOSA_DATAMODEL_SB)AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));

    if ( !pMyObject->pAdvSec->pSafeBrows )
    {
    	CcspTraceError(("%s exit ERROR \n", __FUNCTION__));
    	AnscFreeMemory((ANSC_HANDLE)pMyObject);
        return  (ANSC_HANDLE)NULL;
    }

    pMyObject->pAdvSec->pSoftFlowd = (PCOSA_DATAMODEL_SOFTFLOWD)AnscAllocateMemory(sizeof(COSA_DATAMODEL_SOFTFLOWD));
    if ( !pMyObject->pAdvSec->pSoftFlowd )
    {
    	CcspTraceError(("%s exit ERROR \n", __FUNCTION__));
    	AnscFreeMemory((ANSC_HANDLE)pMyObject);
        return  (ANSC_HANDLE)NULL;
    }

    pMyObject->pAdvPC = (PCOSA_DATAMODEL_ADVPARENTALCONTROL)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVPARENTALCONTROL));
    if ( !pMyObject->pAdvPC )
    {
        CcspTraceError(("%s exit ERROR \n", __FUNCTION__));
        AnscFreeMemory((ANSC_HANDLE)pMyObject);
        return  (ANSC_HANDLE)NULL;
    }

    pMyObject->pPrivProt = (PCOSA_DATAMODEL_PRIVACYPROTECTION)AnscAllocateMemory(sizeof(COSA_DATAMODEL_PRIVACYPROTECTION));
    if ( !pMyObject->pPrivProt )
    {
        CcspTraceError(("%s exit ERROR \n", __FUNCTION__));
        AnscFreeMemory((ANSC_HANDLE)pMyObject);
        return  (ANSC_HANDLE)NULL;
    }

    if (syscfg_init() != 0) {
        CcspTraceError(("%s: syscfg_init error", __FUNCTION__));
    	AnscFreeMemory((ANSC_HANDLE)pMyObject);
        return (ANSC_HANDLE)NULL;
    }

    return  (ANSC_HANDLE)pMyObject;
}


ANSC_STATUS
CosaSecurityInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS             returnStatus        = ANSC_STATUS_SUCCESS;
    ULONG                   Value = 0;
    ULONG                   ValueSB = 0;
    ULONG                   ValueSF = 0;
    ULONG                   ValueAPC = 0;
    ULONG                   ValuePP = 0;

     /* Coverity Fix CID:78774,78899  OVERRUN*/
    char modelName[BUFFERSIZE_MAX]={'\0'};
    char firmwareVersion[64]={'\0'};
    char hardwareVersion[BUFFERSIZE_MAX]={'\0'};
    char deviceMac[64]={'\0'};
    char manufacturer[64]={'\0'};
    errno_t rc = -1;
#if defined(_COSA_BCM_MIPS_)
    dpoe_mac_address_t tDpoe_Mac;
#else
    CMMGMT_CM_DHCP_INFO dhcpinfo;
#endif

    if ( platform_hal_PandMDBInit() == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: PandMDB initiated successfully\n"));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Failed to initiate DB\n"));
    }

#if !defined(_COSA_BCM_MIPS_)
    if ( cm_hal_InitDB() == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: cm_hal DB initiated successfully\n"));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Failed to initiate cm_hal DB\n"));
    }
#endif

    if ( platform_hal_GetModelName(modelName) == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: modelName returned from hal:%s\n", modelName));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get ModelName\n"));
    }

    if ( platform_hal_GetFirmwareName(firmwareVersion, 64) == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: firmwareVersion returned from hal:%s\n", firmwareVersion));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get FirmwareName\n"));
    }

    if ( platform_hal_GetHardwareVersion(hardwareVersion) == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: HardwareVersion returned from hal:%s\n", hardwareVersion));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get HardwareVersion\n"));
    }
 
    if(strlen(CONFIG_VENDOR_NAME) > 0)
    {
        rc = strcpy_s(manufacturer, sizeof(manufacturer), CONFIG_VENDOR_NAME);
        if(rc != EOK)
        {
            ERR_CHK(rc);
        }
        CcspTraceInfo(("CcspAdvSecurity: Manufacturer Name is %s\n", manufacturer));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get Manufacturer Name\n"));
    }

#if defined(_COSA_BCM_MIPS_)
    if( dpoe_getOnuId(&tDpoe_Mac) == 0)
    {
        rc = sprintf_s(deviceMac, sizeof(deviceMac), "%02x:%02x:%02x:%02x:%02x:%02x",tDpoe_Mac.macAddress[0], tDpoe_Mac.macAddress[1],
        tDpoe_Mac.macAddress[2], tDpoe_Mac.macAddress[3], tDpoe_Mac.macAddress[4],tDpoe_Mac.macAddress[5]);
        if(rc < EOK)
        {
            ERR_CHK(rc);
            sleep(30);
            exit(0);
        }
        CcspTraceInfo(("CcspAdvSecurity: deviceMac [%s]\n", deviceMac));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get MACAdress\n"));
        sleep(30);
        exit(0);
    }
#else
    char isEthEnabled[64]={'\0'};
    token_t  token;
    int  ind = -1;
    int fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "advsec", &token);
    if (!fd)
    {
        /* Coverity Fix CID : 125132,125510 PRINTF_ARGS */
        CcspTraceError(("CcspAdvSecurity: Failed to get sysevent fd %d\n", fd));
    }

    char deviceMACValue[32] = { '\0' };
    int found = 0;
    if( 0 == syscfg_get( NULL, "eth_wan_enabled", isEthEnabled, sizeof(isEthEnabled)))
    {
        if(isEthEnabled[0] != '\0')
        {
           rc = strcmp_s(isEthEnabled, sizeof(isEthEnabled), "true", &ind);
           ERR_CHK(rc);
           if(((rc == EOK) && (ind == 0)) && sysevent_get(fd, token, "eth_wan_mac", deviceMACValue, sizeof(deviceMACValue)) == 0 && deviceMACValue[0] != '\0')
           {
               found = 1;
           }
        }
    }
    if(found == 1)
    {
        rc = strcpy_s(deviceMac, sizeof(deviceMac), deviceMACValue);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            sysevent_close(fd, token);
            sleep(30);
            exit(0);
        }
        CcspTraceInfo(("CcspAdvSecurity: deviceMac [%s]\n", deviceMac));
    }
    else if (cm_hal_GetDHCPInfo(&dhcpinfo) == 0 )
    {
          rc = strcmp_s(dhcpinfo.MACAddress, sizeof(dhcpinfo.MACAddress), ADVSEC_DEFAULT_CM_MAC, &ind);
          ERR_CHK(rc);
          if((rc == EOK) && (ind != 0))
          {
              rc = strcpy_s(deviceMac, sizeof(deviceMac), dhcpinfo.MACAddress);
              if(rc != EOK)
              {
                  ERR_CHK(rc);
                  sysevent_close(fd, token);
                  sleep(30);
                  exit(0);
              }
              CcspTraceInfo(("CcspAdvSecurity: deviceMac [%s]\n", deviceMac));
          }
          else
          {
              CcspTraceWarning(("CcspAdvSecurity: Unable to get MACAdress or HAL not ready\n"));
              sysevent_close(fd, token);
              sleep(30);
              exit(0);
          }
    }
    else
    {
        CcspTraceWarning(("CcspAdvSecurity: Unable to get MACAdress or HAL not ready\n"));
        sysevent_close(fd, token);
        sleep(30);
        exit(0);
    }
    /* close this session with syseventd */
    sysevent_close(fd, token);
#endif

    advsec_create_dir(ADVSEC_CONFIG_PARAMS_DIR_PATH);
    if ( ! (advsec_write_to_file(ADVSEC_CONFIG_PARAMS_MODEL_PATH,modelName) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_MNCF_PATH,manufacturer) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_FW_PATH,firmwareVersion) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_HW_PATH,hardwareVersion) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_CM_MAC_PATH,deviceMac)) )
    {
       CcspTraceError(("CcspAdvSecurity: advsec_write_to_file failed\n"));
    }

    CcspTraceInfo(("CcspAdvSecurity: advsec_webconfig_init \n"));
    advsec_webconfig_init();

    CosaGetSysCfgUlong(g_DeviceFingerPrintEnabled, &Value);
    CosaGetSysCfgUlong(g_AdvSecuritySBEnabled, &ValueSB);
    CosaGetSysCfgUlong(g_AdvSecuritySFEnabled, &ValueSF);
    CosaGetSysCfgUlong(g_AdvParentalControl, &ValueAPC);
    CosaGetSysCfgUlong(g_PrivacyProtection, &ValuePP);

    g_pAdvSecAgent->bEnable = Value;
    g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = ValueSB;
    g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = ValueSF;
    g_pAdvSecAgent->pAdvPC->bEnable = ValueAPC;
    g_pAdvSecAgent->pPrivProt->bEnable = ValuePP;

    if(Value == 1)
    {
        returnStatus = CosaAdvSecInit();
        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
        }
    }
    else
    {
        CcspTraceWarning(("\nDevice_Finger_Printing_enabled:false\n"));
    }

    CosaAdvSecGetLoggingPeriod();
    CosaAdvSecGetLookupTimeout();
    advsec_start_logger_thread();
    advsec_handle_sysevent_async();
    return returnStatus;
}


ANSC_STATUS
CosaSecurityRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_AGENT            pMyObject    = (PCOSA_DATAMODEL_AGENT)hThisObject;

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);
    CcspTraceInfo(("%s EXIT \n", __FUNCTION__));

    return returnStatus;
}

ANSC_STATUS CosaGetSysCfgUlong(char* setting, ULONG* value)
{
    char buf[32] = {0};
    ANSC_STATUS         ret = ANSC_STATUS_SUCCESS;

    if(ANSC_STATUS_SUCCESS == (ret = syscfg_get( NULL, setting, buf, sizeof(buf))))
    {
        *value = atol(buf);
    }
    else
    {
        CcspTraceError(("syscfg_get failed\n"));
    }

    return ret;
}

ANSC_STATUS CosaSetSysCfgUlong(char* setting, ULONG value)
{
    ANSC_STATUS         ret = ANSC_STATUS_SUCCESS;
    char buf[32] = {0};
    errno_t rc = -1;

    rc = sprintf_s(buf, sizeof(buf), "%lu", value);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    if(ANSC_STATUS_SUCCESS != (ret = syscfg_set( NULL, setting, buf)))
    {
        CcspTraceError(("syscfg_set failed\n"));
    }
    else
    {
        if (ANSC_STATUS_SUCCESS != (ret = syscfg_commit()))
        {
            CcspTraceError(("syscfg_commit failed\n"));
        }
    }

    return ret;
}

ANSC_STATUS CosaGetSysCfgString(char* setting, char* pValue, PULONG pulSize )
{
    char buf[1024] = {0};
    errno_t rc = -1;

    if(ANSC_STATUS_SUCCESS == syscfg_get( NULL, setting, buf, sizeof(buf)))
    {
        rc = strcpy_s(pValue, *pulSize, buf);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            return ANSC_STATUS_FAILURE;
        }
        *pulSize = AnscSizeOfString(pValue);
        return ANSC_STATUS_SUCCESS;
    }
    else
            return ANSC_STATUS_FAILURE;
}

ANSC_STATUS CosaSetSysCfgString( char* setting, char* pValue )
{
        if ((syscfg_set(NULL, setting, pValue) != 0))
        {
            AnscTraceWarning(("syscfg_set failed\n"));
            return ANSC_STATUS_FAILURE;
        }
        else
        {
            if (syscfg_commit() != 0)
            {
                AnscTraceWarning(("setPartnerId : syscfg_commit failed\n"));
                return ANSC_STATUS_FAILURE;
            }

            return ANSC_STATUS_SUCCESS;
        }
}

ANSC_STATUS CosaAdvSecInit()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[128] = {0};
    errno_t rc = -1;
    rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable &");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    system(cmd);
    g_pAdvSecAgent->bEnable = TRUE;
    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintEnabled, 1);
    return returnStatus;
}

ANSC_STATUS CosaAdvSecDeInit()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[128] = {0};
    errno_t rc = -1;
    rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    system(cmd);
    g_pAdvSecAgent->bEnable = FALSE;

    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintEnabled, 0);
    return returnStatus;
}

static void *advsec_logger_th(void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    char check_log_cmd[COMMAND_MAX];
    char recover_cmd[COMMAND_MAX];
    ULONG remaining_time;
    errno_t rc = -1;

    rc = strcpy_s(check_log_cmd, sizeof(check_log_cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/advsec_log_fp_status.sh check_status &");
    if(rc  != EOK)
    {
        ERR_CHK(rc);
    }
    rc = strcpy_s(recover_cmd, sizeof(recover_cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/advsec_cpu_mem_recovery.sh &");
    if(rc != EOK)
    {
        ERR_CHK(rc);
    }

    remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
    while(1)
    {
        if ( WaitForLoggerTimeout(60 * ADVSEC_MIN_LOG_TIMEOUT) )
        {
            remaining_time = remaining_time - ADVSEC_MIN_LOG_TIMEOUT;

            if ( remaining_time < ADVSEC_MIN_LOG_TIMEOUT && remaining_time != 0 )
            {
                if ( WaitForLoggerTimeout(60 * remaining_time) )
                {
                    remaining_time = 0;
                }
                else
                {
                    remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
                }
            }

            if ( remaining_time == 0 )
            {
                remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
            }

            system(check_log_cmd);
            system(recover_cmd);
        }
        else
        {
            remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
        }
    }
    return NULL;
}

static void advsec_start_logger_thread(void)
{
    int err;
    pthread_t logger_thread;

    err = pthread_create(&logger_thread, NULL, advsec_logger_th, NULL);
    if(0 != err)
    {
        CcspTraceError(("%s: create logger thread error!\n", __FUNCTION__));
    }
}

ANSC_STATUS CosaAdvSecStartFeatures(advsec_feature_type type)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[COMMAND_MAX] = {0};
    errno_t rc = -1;

    if (Is_Device_Finger_Print_Enabled() && !Is_Device_Finger_Print_Enabled_Completed())
    {
       CcspTraceWarning(("%s Device finger print is enabled but not completed yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    switch (type)
    {
        case ADVSEC_SAFEBROWSING:
        if(Is_Device_Finger_Print_Enabled())
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start sb null &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable sb null &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        break;

        case ADVSEC_SOFTFLOWD:
        if(Is_Device_Finger_Print_Enabled())
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start null sf &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable null sf &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        break;

        case ADVSEC_ALL:
        if(Is_Device_Finger_Print_Enabled())
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start sb sf &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable sb sf &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        break;

        default:
       	    return ANSC_STATUS_FAILURE;
        break;
    }

    if(type == ADVSEC_SAFEBROWSING)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = TRUE;
    }

    if(type == ADVSEC_SOFTFLOWD)
    {
	returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
 	g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = TRUE;
    }

    if(type == ADVSEC_ALL)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = TRUE;

        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = TRUE;
        g_pAdvSecAgent->pAdvSec->bEnable = TRUE;
    }

    g_pAdvSecAgent->bEnable = TRUE;
    system(cmd);

    return returnStatus;
}

ANSC_STATUS CosaAdvSecStopFeatures(advsec_feature_type type)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[COMMAND_MAX] = {0};
    errno_t rc = -1;

    switch (type)
    {
        case ADVSEC_SAFEBROWSING:
        if(Is_Device_Finger_Print_Enabled())
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stop sb null &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
         }
        break;

        case ADVSEC_SOFTFLOWD:
        if(Is_Device_Finger_Print_Enabled())
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stop null sf &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            rc = strcpy_s(cmd, sizeof(cmd),  TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        break;

        case ADVSEC_ALL:
        if(Is_Device_Finger_Print_Enabled())
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stop sb sf &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
        }

        break;

        default:
            return returnStatus;
        break;
    }

    if(type == ADVSEC_SAFEBROWSING)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = FALSE;
    }

    if(type == ADVSEC_SOFTFLOWD)
    {
	returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
	g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = FALSE;
    }

    if(type == ADVSEC_ALL)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = FALSE;

        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = FALSE;
        g_pAdvSecAgent->pAdvSec->bEnable = FALSE;
    }

    system(cmd);

    return returnStatus;
}

ANSC_STATUS CosaStartAdvParentalControl(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[COMMAND_MAX] = {0};
    errno_t rc = -1;

    if (!Is_Rabid_Initialization_Completed())
    {
       CcspTraceWarning(("%s Rabid is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvParentalControl, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pAdvPC->bEnable = TRUE;
    }
    rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -startAdvPC &");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }

    system(cmd);

    return returnStatus;
}

ANSC_STATUS CosaStopAdvParentalControl(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[COMMAND_MAX] = {0};
    errno_t rc = -1;

    if (!Is_Rabid_Initialization_Completed())
    {
       CcspTraceWarning(("%s Rabid is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvParentalControl, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pAdvPC->bEnable = FALSE;
    }
    rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stopAdvPC &");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }

    system(cmd);

    return returnStatus;
}

ANSC_STATUS CosaStartPrivacyProtection(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[COMMAND_MAX] = {0};
    errno_t rc = -1;

    if (!Is_Rabid_Initialization_Completed())
    {
       CcspTraceWarning(("%s Rabid is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_PrivacyProtection, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pPrivProt->bEnable = TRUE;
    }
    rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -startPrivProt &");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }

    system(cmd);

    return returnStatus;
}

ANSC_STATUS CosaStopPrivacyProtection(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    char cmd[COMMAND_MAX] = {0};
    errno_t rc = -1;

    if (!Is_Rabid_Initialization_Completed())
    {
       CcspTraceWarning(("%s Rabid is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_PrivacyProtection, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pPrivProt->bEnable = FALSE;
    }
    rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stopPrivProt &");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }

    system(cmd);

    return returnStatus;
}

static ANSC_STATUS advsec_update_feature_status(char *syscfg , BOOL new_val, BOOL *curr_val)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if ( new_val != *curr_val )
    {
         returnStatus = CosaSetSysCfgUlong(syscfg, new_val);
         if ( returnStatus == ANSC_STATUS_SUCCESS )
             *curr_val = new_val;
    }

    return returnStatus;
}

int advsec_webconfig_handle_blob(advsecurityparam_t *feature)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    CcspTraceInfo(("Entering advsec_handle_webconfig_blob\n"));

    if ( feature->fingerprint_enable == g_pAdvSecAgent->bEnable && ! g_pAdvSecAgent->bEnable )
        return ADVSEC_FAILURE;

    returnStatus = advsec_update_feature_status(g_AdvSecuritySBEnabled, feature->safebrowsing_enable, &g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    returnStatus = advsec_update_feature_status(g_AdvSecuritySFEnabled, feature->softflowd_enable, &g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    returnStatus = advsec_update_feature_status(g_AdvParentalControl, feature->parental_control_activate, &g_pAdvSecAgent->pAdvPC->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    returnStatus = advsec_update_feature_status(g_PrivacyProtection, feature->privacy_protection_activate, &g_pAdvSecAgent->pPrivProt->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    if ( feature->fingerprint_enable != g_pAdvSecAgent->bEnable )
    {
        if ( feature->fingerprint_enable )
            returnStatus = CosaAdvSecInit();
        else
            returnStatus = CosaAdvSecDeInit();

        if ( returnStatus != ANSC_STATUS_SUCCESS )
            return SYSCFG_FAILURE;
    }
    else
    {
        char cmd[COMMAND_MAX] = {0};
        errno_t rc = -1;

        rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -configure_features &");
        if(rc != EOK)
        {
            ERR_CHK(rc);
            return SYSCFG_FAILURE;
        }
        system(cmd);
    }

    CcspTraceInfo(("Done advsec_handle_webconfig_blob\n"));
    return BLOB_EXEC_SUCCESS;
}

ANSC_STATUS CosaAdvSecGetLoggingPeriod()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    ULONG value = ADVSEC_DEFAULT_LOG_TIMEOUT;
    returnStatus = CosaGetSysCfgUlong(g_DeviceFingerPrintLogginPeriod, &value);
    g_pAdvSecAgent->ulLoggingPeriod = value;
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSetLoggingPeriod(ULONG value)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintLogginPeriod, value);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        pthread_mutex_lock(&logMutex);
        g_pAdvSecAgent->ulLoggingPeriod = value;
        pthread_cond_signal(&logCond);
        pthread_mutex_unlock(&logMutex);
    }
    return returnStatus;
}

ANSC_STATUS CosaAdvSecGetLookupTimeout()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    ULONG value = ADVSEC_DEFAULT_LOOKUP_TIMEOUT;
    returnStatus = CosaGetSysCfgUlong(g_AdvSecurityLookupTimeout, &value);
    g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout = value;
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSetCustomURL(char* pString)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    returnStatus = CosaSetSysCfgString(g_DeviceFingerPrintEndpointURL, pString);
    return returnStatus;
}

ANSC_STATUS CosaAdvSecGetCustomURL(char* pValue, PULONG pUlSize)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    returnStatus = CosaGetSysCfgString(g_DeviceFingerPrintEndpointURL, pValue, pUlSize);
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSetLookupTimeout(ULONG value)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    returnStatus = CosaSetSysCfgUlong(g_AdvSecurityLookupTimeout, value);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout = value;
        if (g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable == TRUE)
        {
            char cmd[COMMAND_MAX] = {0};
            errno_t rc = -1;
            rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start sb null &");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }
            system(cmd);
        }
    }
    else
    {
        CcspTraceError(("CosaAdvSecSetLookupTimeout: failed\n"));
    }
    return returnStatus;
}

ULONG CosaAdvSecGetLookupTimeoutExceededCount()
{
    ULONG lcount = 0;
    FILE *fp;
    char buf[COMMAND_MAX] = {0};

    fp = fopen(ADVSEC_LOOKUP_EXCEED_COUNT_FILE, "r");
    if ( fp != NULL)
    {
        fgets(buf, COMMAND_MAX, (FILE*)fp);
        fclose(fp);
        lcount = atol(buf);
    }

    return lcount;
}

static BOOL AdvsecSysEventHandlerStarted=FALSE;
static int sysevent_fd = 0;
static token_t sysEtoken;
static async_id_t async_id[6];

enum {SYS_EVENT_ERROR=-1, SYS_EVENT_OK, SYS_EVENT_TIMEOUT, SYS_EVENT_HANDLE_EXIT, SYS_EVENT_RECEIVED=0x10};

/*
 * Initialize sysevnt
 *   return 0 if success and -1 if failure.
 */
int advsec_sysevent_init(void)
{
    int rc;

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "advsec", &sysEtoken);
    if (!sysevent_fd) {
        return(SYS_EVENT_ERROR);
    }

    /*you can register the event as you want*/

    //register event
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_PARENTAL_CONTROL_RFC_EVENT, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_PARENTAL_CONTROL_RFC_EVENT, &async_id[0]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    //register privacy event
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_PRIVACY_PROTECTION_RFC_EVENT, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_PRIVACY_PROTECTION_RFC_EVENT, &async_id[1]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    //register bridge mode event
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT, &async_id[2]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    //register host to IP address
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_CLOUD_HOST_IP, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_CLOUD_HOST_IP, &async_id[3]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    //register rabid non-root event
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_RABID_NONROOT_RFC_EVENT, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_RABID_NONROOT_RFC_EVENT, &async_id[4]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    return(SYS_EVENT_OK);
}

/*
* Sysevent handler.
*/
void advsec_handle_sysevent_notification(char *event, char *val)
{
    enum advSysEvent_e type;

    if(!event || !val)
        return;

    CcspTraceWarning(("CcspAdvSecurity: Received notification event:val %s:%s\n", event,val));

    if(get_advSysEvent_type_from_name(event, &type))
    {
        if(type == SYSEVENT_PARENTAL_CONTROL_RFC_EVENT)
        {
            if(g_pAdvSecAgent->pAdvPC->bEnable)
            {
                if((val[0] == '0') && (val[1] == '\0'))
                {
                    CcspTraceWarning(("CcspAdvSecurity: Received Adv parental control RFC disable\n"));
                    CosaStopAdvParentalControl(FALSE);
                }

                if((val[0] == '1') && (val[1] == '\0'))
                {
                    CcspTraceWarning(("CcspAdvSecurity: Received Adv parental control RFC enable\n"));
                    CosaStartAdvParentalControl(FALSE);
                }
            }
        }
        else if(type == SYSEVENT_PRIVACY_PROTECTION_RFC_EVENT)
        {
            if(g_pAdvSecAgent->pPrivProt->bEnable)
            {
               if((val[0] == '0') && (val[1] == '\0'))
               {
                   CcspTraceWarning(("CcspAdvSecurity: Received Privacy Protection RFC disable\n"));
                   CosaStopPrivacyProtection(FALSE);
               }

               if((val[0] == '1') && (val[1] == '\0'))
               {
                   CcspTraceWarning(("CcspAdvSecurity: Received Privacy Protection RFC enable\n"));
                   CosaStartPrivacyProtection(FALSE);
               }
            }
        }
        else if(type == SYSEVENT_BRIDGE_MODE_EVENT)
        {
            char cmd[COMMAND_MAX] = {0};
            errno_t rc = -1;

            if((val[0] == '0') && (val[1] == '\0'))
            {
                CcspTraceWarning(("CcspAdvSecurity: Received Bridge Mode Off\n"));
                rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable &");
                if(rc != EOK)
                {
                     ERR_CHK(rc);
                     return;
                }
                system(cmd);
            }

            if((val[0] == '2') && (val[1] == '\0'))
            {
                CcspTraceWarning(("CcspAdvSecurity: Received Bridge Mode On\n"));
                rc = strcpy_s(cmd, sizeof(cmd), TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return;
                }
                system(cmd);
            }
        }
        else if(type == SYSEVENT_CLOUD_HOST_IP)
        {
            char url[COMMAND_MAX];
            memset(url, 0, sizeof(url));

            if (advsec_read_from_file(ADVSEC_CLOUD_HOST,url))
            {
                char *host1 = NULL;
                char *host2 = NULL;
                char *port = NULL;
                char *ip = NULL;
                if ((host1 = strtok(url, ":")) != NULL)
                {
                    port = strtok(NULL, ":");

                    if ((host2 = strtok(val, ":")) != NULL)
                    {
                       ip = strtok(NULL, ":");
                    }

                    if ( port && ip && strcmp(host1,host2) == 0)
                    {
                        char ip_port[COMMAND_MAX];
                        memset(ip_port, 0, sizeof(ip_port));
                        strcpy(ip_port,ip);
                        strcat(ip_port,":");
                        strcat(ip_port,port);
                        CcspTraceWarning(("CcspAdvSecurity: cloud ip:port %s\n",ip_port));
                        if ( ! advsec_write_to_file(ADVSEC_CLOUD_IP,ip_port) )
                        {
                            CcspTraceError(("CcspAdvSecurity: advsec_write_to_file failed\n"));
                        }
                    }
                }
            }
        }
        else if(type == SYSEVENT_RABID_NONROOT_RFC_EVENT)
        {
            char cmd[COMMAND_MAX];
            memset(cmd, 0, sizeof(cmd));

            if (strcmp(val,"0") == 0 || strcmp(val,"1") == 0)
            {
                AnscCopyString(cmd, TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -restart &");
                system(cmd);
            }
        }
    }

    return;
}
/*
 * Listen sysevent notification message
 */
int advsec_sysvent_listener(void)
{
    int     ret = SYS_EVENT_TIMEOUT;
    struct  timeval;

    char name[COMMAND_MAX], val[256];
    int namelen = sizeof(name);
    int vallen	= sizeof(val);
    int err;
    async_id_t getnotification_asyncid;

    err = sysevent_getnotification(sysevent_fd, sysEtoken, name, &namelen,  val, &vallen, &getnotification_asyncid);
    if (err)
    {
        CcspTraceError(("sysevent_getnotification failed with error: %d\n", err));
    }
    else
    {
        advsec_handle_sysevent_notification(name,val);
	ret = SYS_EVENT_RECEIVED;
    }

    return ret;
}

/*
 * Close sysevent
 */
int advsec_sysvent_close(void)
{
    /* we are done with this notification, so unregister it using async_id provided earlier */
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[0]);
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[1]);
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[2]);
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[3]);
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[4]);

    /* close this session with syseventd */
    sysevent_close(sysevent_fd, sysEtoken);

    return (SYS_EVENT_OK);
}

/*
 * check the initialized sysevent status (happened or not happened),
 * if the event happened, call the functions registered for the events previously
 */
int advsec_check_sysevent_status(int fd, token_t token)
{
    UNREFERENCED_PARAMETER(fd);
    UNREFERENCED_PARAMETER(token);
    int  returnStatus = ANSC_STATUS_SUCCESS;

    return returnStatus;
}


/*
 * The sysevent handler thread.
 */
static void *advsec_sysevent_handler_th(void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    int ret = SYS_EVENT_ERROR;

    while(SYS_EVENT_ERROR == advsec_sysevent_init())
    {
        CcspTraceError(("%s: sysevent init failed!\n", __FUNCTION__));
        sleep(1);
    }

    /*first check the events status*/
    advsec_check_sysevent_status(sysevent_fd, sysEtoken);

    while(1)
    {
        ret = advsec_sysvent_listener();
        switch (ret)
        {
            case SYS_EVENT_RECEIVED:
                break;
            default :
                CcspTraceError(("The received event status is not expected!\n"));
                break;
        }

        if (SYS_EVENT_HANDLE_EXIT == ret) //end this event handling loop
            break;

        sleep(2);
    }

    advsec_sysvent_close();

    return NULL;
}


/*
 * Create a thread to handle the sysevent asynchronously
 */
void advsec_handle_sysevent_async(void)
{
    int err;
    pthread_t event_handle_thread;

    if(AdvsecSysEventHandlerStarted)
        return;
    else
        AdvsecSysEventHandlerStarted = TRUE;

    err = pthread_create(&event_handle_thread, NULL, advsec_sysevent_handler_th, NULL);
    if(0 != err)
    {
        CcspTraceError(("%s: create the event handle thread error!\n", __FUNCTION__));
    }
}

static BOOL WaitForLoggerTimeout(ULONG period)
{
    struct timespec _ts = {0};
    struct timespec _now = {0};
    int n;
    BOOL ret = TRUE;

    pthread_mutex_lock(&logMutex);

    clock_gettime(CLOCK_REALTIME, &_now);
    _ts.tv_sec = _now.tv_sec + period;
    n = pthread_cond_timedwait(&logCond, &logMutex, &_ts);
    if(n == ETIMEDOUT)
    {
        ret = TRUE;
    }
    else
    {
        ret = FALSE;
    }

    pthread_mutex_unlock(&logMutex);
    return ret;
}
