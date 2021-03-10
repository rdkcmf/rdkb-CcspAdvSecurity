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
   
#include "cosa_adv_security_dml.h"

#include "ansc_platform.h"
#include "cosa_adv_security_internal.h"
#include "cosa_adv_security_webconfig.h"
#include "syslog.h"
#include "ccsp_trace.h"
#include "msgpack.h"
#include "advsecurity_param.h"
#include "base64.h"
#include "safec_lib_common.h"

extern COSA_DATAMODEL_AGENT* g_pAdvSecAgent;

static int urlStartsWith(const char *haystack, const char *needle)
{
   if(strncmp(haystack, needle, strlen(needle)) == 0)
       return 0;
   return 1;
}

ANSC_STATUS isValidUrl( char *inputparam )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    if(urlStartsWith(inputparam, "https://"))
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    if(strstr(inputparam,";")) // check for possible command injection 
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    else if(strstr(inputparam,"&"))
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    else if(strstr(inputparam,"|"))
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    else if(strstr(inputparam,"'"))
        returnStatus = ANSC_STATUS_FAILURE;

    return returnStatus;
}

/***********************************************************************

 APIs for Object:

	X_RDKCENTRAL-COM_DeviceFingerPrint.

    *  DeviceFingerPrint_GetParamBoolValue
    *  DeviceFingerPrint_SetParamBoolValue
    *  DeviceFingerPrint_GetParamUlongValue
    *  DeviceFingerPrint_SetParamUlongValue
    *  DeviceFingerPrint_GetParamStringValue
    *  DeviceFingerPrint_SetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DeviceFingerPrint_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        *pBool = pMyObject->bEnable;
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrint_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if(bValue == pMyObject->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecInit(pMyObject);
        else
                returnStatus = CosaAdvSecDeInit(pMyObject);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrint_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve Unsigned Long parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned unsigned long value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("LoggingPeriod", strlen("LoggingPeriod"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        *puLong = g_pAdvSecAgent->ulLoggingPeriod;
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrint_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       bValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("LoggingPeriod", strlen("LoggingPeriod"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( bValue < ADVSEC_MIN_LOG_TIMEOUT || bValue > ADVSEC_MAX_LOG_TIMEOUT )
        {
            CcspTraceInfo(("%s Values out of range\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->ulLoggingPeriod)
                return TRUE;

        returnStatus = CosaAdvSecSetLoggingPeriod(bValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DeviceFingerPrint_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
DeviceFingerPrint_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return -1;

    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("EndpointURL", strlen("EndpointURL"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        returnStatus = CosaAdvSecGetCustomURL(pValue, pUlSize);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DeviceFingerPrint_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("EndpointURL", strlen("EndpointURL"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if(ANSC_STATUS_SUCCESS == isValidUrl(pString))
        {
            returnStatus = CosaAdvSecSetCustomURL(pString);

            if ( returnStatus != ANSC_STATUS_SUCCESS )
            {
                CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
                return  returnStatus;
            }
            return TRUE;
        }
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedSecurity_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedSecurity_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;
    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("Data", strlen("Data"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        advsecuritydoc_t *ad = NULL;
        int err;
        char * decodeMsg =NULL;
        int decodeMsgSize =0;
        int size =0;
        BOOL ret_val = TRUE;

        msgpack_zone mempool;
        msgpack_object deserialized;
        msgpack_unpack_return unpack_ret;

        decodeMsgSize = b64_get_decoded_buffer_size(strlen(pString));
        decodeMsg = (char *) AnscAllocateMemory(sizeof(char) * decodeMsgSize);
        size = b64_decode((uint8_t *) pString, strlen(pString),(uint8_t *) decodeMsg );
        CcspTraceInfo(("base64 decoded data contains %d bytes\n",size));

        msgpack_zone_init(&mempool, 2048);
        unpack_ret = msgpack_unpack(decodeMsg, size, NULL, &mempool, &deserialized);
        switch(unpack_ret)
        {
            case MSGPACK_UNPACK_SUCCESS:
                CcspTraceInfo(("MSGPACK_UNPACK_SUCCESS :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_EXTRA_BYTES:
                CcspTraceInfo(("MSGPACK_UNPACK_EXTRA_BYTES :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_CONTINUE:
                CcspTraceInfo(("MSGPACK_UNPACK_CONTINUE :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_PARSE_ERROR:
                CcspTraceError(("MSGPACK_UNPACK_PARSE_ERROR :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_NOMEM_ERROR:
                CcspTraceError(("MSGPACK_UNPACK_NOMEM_ERROR :%d\n",unpack_ret));
            break;
            default:
                CcspTraceError(("Message Pack decode failed with error: %d\n", unpack_ret));
        }
        msgpack_zone_destroy(&mempool);

        CcspTraceInfo(("---------------End of b64 decode--------------\n"));

        if(unpack_ret == MSGPACK_UNPACK_SUCCESS)
        {
            CcspTraceInfo(("Msg unpack success\n"));
            ad = advsecuritydoc_convert(decodeMsg, size);//used to process the incoming msgobject
            err = errno;
            CcspTraceInfo(("errno: %s\n", advsecuritydoc_strerror(err)));

            if(ad != NULL)
            {
                CcspTraceInfo(("ad->subdoc_name is %s\n", ad->subdoc_name));
                CcspTraceInfo(("ad->version is %lu\n", (long)ad->version));
                CcspTraceInfo(("ad->transaction_id %lu\n",(long) ad->transaction_id));
                CcspTraceInfo(("fingerprint_enable:[%d], softflowd_enable[%d], safebrowsing_enable[%d], parental_control_activate[%d], privacy_protection_activate[%d]\n",
                    ad->param->fingerprint_enable,ad->param->softflowd_enable,ad->param->safebrowsing_enable,
                    ad->param->parental_control_activate,ad->param->privacy_protection_activate));

                execData *execDataAdvsec = NULL ;
                execDataAdvsec = (execData*) AnscAllocateMemory (sizeof(execData));

                if ( execDataAdvsec != NULL )
                {
                    rc = memset_s(execDataAdvsec, sizeof(execData), 0, sizeof(execData));
                    ERR_CHK(rc);

                    execDataAdvsec->txid = ad->transaction_id;
                    execDataAdvsec->version = ad->version;
                    execDataAdvsec->numOfEntries = 1;

                    rc = strcpy_s(execDataAdvsec->subdoc_name, sizeof(execDataAdvsec->subdoc_name), ad->subdoc_name);
                    if(rc != EOK)
                    {
                       ERR_CHK(rc);
                       if(execDataAdvsec)
                       {
                           AnscFreeMemory(execDataAdvsec);
                           execDataAdvsec = NULL;
                       }
                       if(decodeMsg)
                       {
                            AnscFreeMemory(decodeMsg);
                            decodeMsg = NULL;
                       }
                       return FALSE;
                    }

                    execDataAdvsec->user_data = (void*) ad;
                    execDataAdvsec->calcTimeout = NULL ;
                    execDataAdvsec->executeBlobRequest = advsec_webconfig_process_request;
                    execDataAdvsec->rollbackFunc = advsec_webconfig_rollback;
                    execDataAdvsec->freeResources = advsec_webconfig_free_resources;
                    PushBlobRequest(execDataAdvsec);
                    CcspTraceInfo(("PushBlobRequest complete\n"));
                }
                else
                {
                    CcspTraceError(("execData AnscAllocateMemory failed\n"));
                    advsecuritydoc_destroy(ad);
                    ret_val = FALSE;
                }
            }
        }
        else
        {
            CcspTraceError(("Failed to unpack megpack\n"));
            ret_val = FALSE;
        }

        if ( decodeMsg )
        {
                AnscFreeMemory (decodeMsg);
                decodeMsg = NULL;
        }
        return ret_val;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/***********************************************************************

 APIs for Object:

	X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.

    *  SafeBrowsing_GetParamBoolValue
    *  SafeBrowsing_SetParamBoolValue
    *  SafeBrowsing_GetParamUlongValue
    *  SafeBrowsing_SetParamUlongValue
    *  SafeBrowsing_Validate
    *  SafeBrowsing_Commit
    *  SafeBrowsing_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SafeBrowsing_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    if(ParamName == NULL)
        return FALSE;
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable;
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SafeBrowsing_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    errno_t rc = -1;
    int ind = -1;

    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING);
        else
                returnStatus = CosaAdvSecStopFeatures(ADVSEC_SAFEBROWSING);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SafeBrowsing_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve Unsigned Long parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned unsigned long value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    errno_t rc = -1;
    int ind = -1;
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("LookupTimeout", strlen("LookupTimeout"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *puLong = g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout;
        return TRUE;
    }

    rc = strcmp_s("LookupTimeoutExceededCount", strlen("LookupTimeoutExceededCount"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *puLong = CosaAdvSecGetLookupTimeoutExceededCount();
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SafeBrowsing_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       bValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;
    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("LookupTimeout", strlen("LookupTimeout"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if ( bValue < ADVSEC_DEFAULT_LOOKUP_TIMEOUT || bValue > ADVSEC_MAX_LOOKUP_TIMEOUT )
        {
            CcspTraceWarning(("%s Values out of range\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout)
                return TRUE;

        returnStatus = CosaAdvSecSetLookupTimeout(bValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SafeBrowsing_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
SafeBrowsing_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SafeBrowsing_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SafeBrowsing_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SafeBrowsing_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SafeBrowsing_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/***********************************************************************

 APIs for Object:

	X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.

    *  Softflowd_GetParamBoolValue
    *  Softflowd_SetParamBoolValue
    *  Softflowd_Validate
    *  Softflowd_Commit
    *  Softflowd_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Softflowd_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Softflowd_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable;
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Softflowd_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Softflowd_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecStartFeatures(ADVSEC_SOFTFLOWD);
        else
                returnStatus = CosaAdvSecStopFeatures(ADVSEC_SOFTFLOWD);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Softflowd_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
Softflowd_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Softflowd_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Softflowd_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Softflowd_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Softflowd_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/***********************************************************************

 APIs for Object:

        X_RDKCENTRAL-COM_AdvancedParentalControl.

    *  AdvancedParentalControl_GetParamBoolValue
    *  AdvancedParentalControl_SetParamBoolValue
    *  AdvancedParentalControl_Validate
    *  AdvancedParentalControl_Commit
    *  AdvancedParentalControl_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedParentalControl_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedParentalControl_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pAdvPC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedParentalControl_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedParentalControl_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvPC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaStartAdvParentalControl(TRUE);
        else
                returnStatus = CosaStopAdvParentalControl(TRUE);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedParentalControl_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
AdvancedParentalControl_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(puLength);
    UNREFERENCED_PARAMETER(pReturnParamName);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AdvancedParentalControl_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
AdvancedParentalControl_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AdvancedParentalControl_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
AdvancedParentalControl_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/***********************************************************************

 APIs for Object:

        X_RDKCENTRAL-COM_PrivacyProtection.

    *  PrivacyProtection_GetParamBoolValue
    *  PrivacyProtection_SetParamBoolValue
    *  PrivacyProtection_Validate
    *  PrivacyProtection_Commit
    *  PrivacyProtection_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PrivacyProtection_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PrivacyProtection_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pPrivProt->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PrivacyProtection_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PrivacyProtection_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pPrivProt->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaStartPrivacyProtection(TRUE);
        else
                returnStatus = CosaStopPrivacyProtection(TRUE);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PrivacyProtection_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
PrivacyProtection_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PrivacyProtection_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PrivacyProtection_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PrivacyProtection_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PrivacyProtection_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}
