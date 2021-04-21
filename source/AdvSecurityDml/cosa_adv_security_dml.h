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
#ifndef  _COSA_ADV_SECURITY_DML_H
#define  _COSA_ADV_SECURITY_DML_H

#include "slap_definitions.h"

ANSC_STATUS
CosaDmlServiceManagerInit
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_DeviceFingerPrint.

    *  DeviceFingerPrint_GetParamBoolValue
    *  DeviceFingerPrint_SetParamBoolValue
    *  DeviceFingerPrint_GetParamStringValue
    *  DeviceFingerPrint_SetParamStringValue
    *  DeviceFingerPrint_GetParamUlongValue
    *  DeviceFingerPrint_SetParamUlongValue

***********************************************************************/
BOOL
DeviceFingerPrint_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
DeviceFingerPrint_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

ULONG
DeviceFingerPrint_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
DeviceFingerPrint_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
DeviceFingerPrint_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );
BOOL
DeviceFingerPrint_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       bValue

    );

BOOL
AdvancedSecurity_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

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
BOOL
SafeBrowsing_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
SafeBrowsing_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );
BOOL
SafeBrowsing_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                       puLong
    );

BOOL
SafeBrowsing_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       bValue
    );
BOOL
SafeBrowsing_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
SafeBrowsing_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
SafeBrowsing_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.

    *  Softflowd_GetParamBoolValue
    *  Softflowd_SetParamBoolValue
    *  Softflowd_Validate
    *  Softflowd_Commit
    *  Softflowd_Rollback

***********************************************************************/
BOOL
Softflowd_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
Softflowd_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
Softflowd_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
Softflowd_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
Softflowd_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_AdvancedParentalControl.

    *  AdvancedParentalControl_GetParamBoolValue
    *  AdvancedParentalControl_SetParamBoolValue
    *  AdvancedParentalControl_Validate
    *  AdvancedParentalControl_Commit
    *  AdvancedParentalControl_Rollback

***********************************************************************/
BOOL
AdvancedParentalControl_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
AdvancedParentalControl_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );
BOOL
AdvancedParentalControl_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
AdvancedParentalControl_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
AdvancedParentalControl_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_PrivacyProtection.

    *  PrivacyProtection_GetParamBoolValue
    *  PrivacyProtection_SetParamBoolValue
    *  PrivacyProtection_Validate
    *  PrivacyProtection_Commit
    *  PrivacyProtection_Rollback

***********************************************************************/
BOOL
PrivacyProtection_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
PrivacyProtection_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );
BOOL
PrivacyProtection_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
PrivacyProtection_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
PrivacyProtection_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RabidFramework.

    *  RabidFramework_GetParamUlongValue
    *  RabidFramework_SetParamUlongValue

***********************************************************************/
BOOL
RabidFramework_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

BOOL
RabidFramework_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_AdvancedParentalControl.

    *  AdvancedParentalControl_GetParamBoolValue
    *  AdvancedParentalControl_SetParamBoolValue

***********************************************************************/
BOOL
AdvancedParentalControl_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
AdvancedParentalControl_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_PrivacyProtection.

    *  PrivacyProtection_GetParamBoolValue
    *  PrivacyProtection_SetParamBoolValue

***********************************************************************/
BOOL
PrivacyProtection_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
PrivacyProtection_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );
#endif //_COSA_ADV_SECURITY_DML_H
