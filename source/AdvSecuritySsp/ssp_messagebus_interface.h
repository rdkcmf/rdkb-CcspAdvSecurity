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

/**********************************************************************

    module: ssp_messagebus_interface.h

    ---------------------------------------------------------------

    description:

        The header file for the CCSP Message Bus Interface
        Service.

**********************************************************************/

#ifndef  _SSP_MESSAGEBUS_INTERFACE_
#define  _SSP_MESSAGEBUS_INTERFACE_

ANSC_STATUS
ssp_AdvsecMbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    );

int
ssp_AdvsecMbi_Initialize
    (
        void * user_data
    );

int
ssp_AdvsecMbi_Finalize
    (
        void * user_data
    );

int
ssp_AdvsecMbi_Buscheck
    (
        void * user_data
    );

int
ssp_AdvsecMbi_GetHealth
	(
		void
	);

int
ssp_AdvsecMbi_FreeResources
    (
        int priority,
        void * user_data
    );

ANSC_STATUS
ssp_AdvsecMbi_SendParameterValueChangeSignal
    (
        char * pPamameterName,
        SLAP_VARIABLE * oldValue,
        SLAP_VARIABLE * newValue,
        char * pAccessList
    );

ANSC_STATUS
ssp_AdvsecMbi_SendTransferCompleteSignal
    (
        void
    );

DBusHandlerResult
CcspAdvSec_path_message_func
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    );

/*
static DBusHandlerResult
path_message_func
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    );
*/

/*
ANSC_STATUS
ssp_XdnsMbi_RegisterToCR
    (
        ANSC_HANDLE                     hThisObject,
        name_spaceType_t*               pParameterArray
    );

*/
void 
ssp_AdvsecMbi_WaitConditionReady
	(
		void* 							bus_handle, 
		const char* 					dst_component_id,
		char* 							dbus_path,
		char*							src_component_id
	);

#endif
