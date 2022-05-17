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

#include <stdarg.h>
#include "mock_advsec_internal.h"

extern AdvsecInternalMock * g_AdvsecInternalMock;     /* This is just a declaration! The actual mock
                                                        obj is defined globally in the test file. */

// Mock Method
extern "C" int v_secure_system(const char * cmd, ...)
{
    if (!g_AdvsecInternalMock)
    {
        return 0;
    }

    char format[250] = { 0 };

    va_list argptr;
    va_start(argptr, cmd);
    vsnprintf(format, sizeof(format), cmd, argptr);
    va_end(argptr);

    return g_AdvsecInternalMock->v_secure_system(format);
}

extern "C" ANSC_STATUS CosaGetSysCfgUlong(char * setting, ULONG* value)
{
    if (!g_AdvsecInternalMock)
    {
        return 0;
    }
    return g_AdvsecInternalMock->CosaGetSysCfgUlong(setting, value);
}

extern "C" ANSC_STATUS CosaSetSysCfgUlong(char * setting, ULONG value)
{
    if (!g_AdvsecInternalMock)
    {
        return 0;
    }
    return g_AdvsecInternalMock->CosaSetSysCfgUlong(setting, value);
}