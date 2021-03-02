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

    module: ssp_messagebus_interface.c

        For Advanced Security module

    description:

        SSP implementation of the CCSP Message Bus Interface
        Service.

        *   ssp_AdvsecMbi_MessageBusEngage
        *   ssp_AdvsecMbi_EventCallback

**********************************************************************/

#include "ssp_global.h"


extern  PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm;

void ssp_AdvsecMbi_WaitConditionReady(void* bus_handle, const char* dst_component_id, char* dbus_path, char *src_component_id)
{
    UNREFERENCED_PARAMETER(bus_handle);
    UNREFERENCED_PARAMETER(dst_component_id);
    UNREFERENCED_PARAMETER(dbus_path);
    UNREFERENCED_PARAMETER(src_component_id);
	return;
}

int ssp_AdvsecMbi_GetHealth(void)
{
    return -1;
}

