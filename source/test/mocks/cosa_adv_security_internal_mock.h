/*
* Copyright 2020 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

/*
* ANSC STATUS Handle
*/
#define ANSC_STATUS_SUCCESS 0
#define ANSC_STATUS_FAILURE 0xFFFFFFFF
#define EOK 0
#define TRUE 1
#define FALSE 0

/*
*   adv_security_internal.c structure declaration
*/

typedef  unsigned char              UCHAR,          *PUCHAR;
typedef  unsigned long              ULONG,          *PULONG;
typedef  UCHAR                      BOOL,           *PBOOL;
typedef  ULONG                  ANSC_STATUS,     *PANSC_STATUS;
typedef  void*                  PVOID;
typedef  PVOID                  ANSC_HANDLE,     *PANSC_HANDLE;

typedef enum {
    ADVSEC_SAFEBROWSING=0,
    ADVSEC_SOFTFLOWD,
    DUMMY_NEGATIVECASE_CHECK,
    ADVSEC_ALL=255
}advsec_feature_type;

typedef  struct
_COSA_DATAMODEL_AGENT_SOFTFLOWD {
    BOOL   bEnable;
}
COSA_DATAMODEL_SOFTFLOWD;

typedef  struct
_COSA_DATAMODEL_AGENT_SB {
    BOOL   bEnable;
}
COSA_DATAMODEL_SB;

typedef  struct
_COSA_DATAMODEL_RAPTR_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_RAPTR_RFC;

typedef  struct
_COSA_DATAMODEL_AGENT_ADVSEC {
    BOOL   bEnable;
    COSA_DATAMODEL_SB   *pSafeBrows;
    COSA_DATAMODEL_SOFTFLOWD    *pSoftFlowd;
}
COSA_DATAMODEL_ADVSEC;

typedef  struct
_COSA_DATAMODEL_AGENT
{
    BOOL                bEnable;
    COSA_DATAMODEL_ADVSEC      *pAdvSec;
    COSA_DATAMODEL_RAPTR_RFC   *pRaptr_RFC;
}
COSA_DATAMODEL_AGENT;

/*
*   adv_security_internal.c standard function declaration
*/
ANSC_STATUS
CosaAdvSecStartFeatures
    (
        advsec_feature_type type
    );

ANSC_STATUS
CosaAdvSecStopFeatures
    (
        advsec_feature_type type
    );

ANSC_STATUS
CosaAdvSecAgentRaptrInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecAgentRaptrDeInit
    (
        ANSC_HANDLE hThisObject
    );