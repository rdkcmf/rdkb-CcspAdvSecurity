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

#include <stdio.h>
#include <string.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "test/mocks/mock_advsec_internal.h"

extern "C" {
#include "test/mocks/cosa_adv_security_internal_mock.h"
COSA_DATAMODEL_AGENT *g_pAdvSecAgent = NULL;
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

AdvsecInternalMock * g_AdvsecInternalMock = NULL;  /* This is the actual definition of the mock obj */

class CcspAdvSecurityDmlTestFixture : public ::testing::Test {
    protected:
        AdvsecInternalMock mockedAdvsecInternal;

        CcspAdvSecurityDmlTestFixture()
        {
            g_AdvsecInternalMock = &mockedAdvsecInternal;
        }
        virtual ~CcspAdvSecurityDmlTestFixture()
        {
            g_AdvsecInternalMock = NULL;
        }
};

TEST_F(CcspAdvSecurityDmlTestFixture, ccsp_advsec_start_features_sb)
{
    const advsec_feature_type type = ADVSEC_SAFEBROWSING;
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -start sb null &";
    ULONG expectedSBEnable = 1;
    char *AdvSecuritySBEnabled = "Advsecurity_SafeBrowsing";
    char *fname = "/tmp/advsec_initialized";
    int val = 0;
    FILE* file = NULL;

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec = (COSA_DATAMODEL_ADVSEC *)malloc(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!(g_pAdvSecAgent->pAdvSec))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSafeBrows = (COSA_DATAMODEL_SB *)malloc(sizeof(COSA_DATAMODEL_SB));
    if (!(g_pAdvSecAgent->pAdvSec->pSafeBrows))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = FALSE;
    g_pAdvSecAgent->bEnable = TRUE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySBEnabled), expectedSBEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    if ((file = fopen(fname, "r")))
    {
       fclose(file);
    }
    else
    {
       file = fopen(fname, "w");
       fclose(file);
       val = 1;
    }

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecStartFeatures(type));
    EXPECT_EQ(TRUE, g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable);

    if ( val == 1)
    remove(fname);

    free(g_pAdvSecAgent->pAdvSec->pSafeBrows);
    free(g_pAdvSecAgent->pAdvSec);
    free(g_pAdvSecAgent);
}

TEST_F(CcspAdvSecurityDmlTestFixture, ccsp_advsec_start_features_sf)
{
    const advsec_feature_type type = ADVSEC_SOFTFLOWD;
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -start null sf &";
    ULONG expectedSFEnable = 1;
    char *AdvSecuritySFEnabled = "Advsecurity_Softflowd";
    char *fname = "/tmp/advsec_initialized";
    int val = 0;
    FILE* file = NULL;

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec = (COSA_DATAMODEL_ADVSEC *)malloc(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!(g_pAdvSecAgent->pAdvSec))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSoftFlowd = (COSA_DATAMODEL_SOFTFLOWD *)malloc(sizeof(COSA_DATAMODEL_SOFTFLOWD));
    if (!(g_pAdvSecAgent->pAdvSec->pSoftFlowd))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = FALSE;
    g_pAdvSecAgent->bEnable = TRUE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySFEnabled), expectedSFEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    if ((file = fopen(fname, "r")))
    {
       fclose(file);
    }
    else
    {
       file = fopen(fname, "w");
       fclose(file);
       val = 1;
    }

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecStartFeatures(type));
    EXPECT_EQ(TRUE, g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable);

    if(val == 1)
    remove(fname);

    free(g_pAdvSecAgent->pAdvSec->pSoftFlowd);
    free(g_pAdvSecAgent->pAdvSec);
    free(g_pAdvSecAgent);
}

TEST_F(CcspAdvSecurityDmlTestFixture, ccsp_advsec_start_features_sb_sf)
{
    const advsec_feature_type type = ADVSEC_ALL;
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -start sb sf &";
    ULONG expectedSBSFEnable = 1;
    char *AdvSecuritySBEnabled = "Advsecurity_SafeBrowsing";
    char *AdvSecuritySFEnabled = "Advsecurity_Softflowd";
    char *fname = "/tmp/advsec_initialized";
    int val = 0;
    FILE* file = NULL;

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec = (COSA_DATAMODEL_ADVSEC *)malloc(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!(g_pAdvSecAgent->pAdvSec))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSoftFlowd = (COSA_DATAMODEL_SOFTFLOWD *)malloc(sizeof(COSA_DATAMODEL_SOFTFLOWD));
    if (!(g_pAdvSecAgent->pAdvSec->pSoftFlowd))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSafeBrows = (COSA_DATAMODEL_SB *)malloc(sizeof(COSA_DATAMODEL_SB));
    if (!(g_pAdvSecAgent->pAdvSec->pSafeBrows))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec->pSoftFlowd);
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = FALSE;
    g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = FALSE;
    g_pAdvSecAgent->pAdvSec->bEnable = TRUE;
    g_pAdvSecAgent->bEnable = TRUE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySBEnabled), expectedSBSFEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySFEnabled), expectedSBSFEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    if ((file = fopen(fname, "r")))
    {
       fclose(file);
    }
    else
    {
       file = fopen(fname, "w");
       fclose(file);
       val = 1;
    }

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecStartFeatures(type));
    EXPECT_EQ(TRUE, g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable);
    EXPECT_EQ(TRUE, g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable);

    if(val == 1)
    remove(fname);

    free(g_pAdvSecAgent->pAdvSec->pSafeBrows);
    free(g_pAdvSecAgent->pAdvSec->pSoftFlowd);
    free(g_pAdvSecAgent->pAdvSec);
    free(g_pAdvSecAgent);
}

TEST_F(CcspAdvSecurityDmlTestFixture, ccsp_advsec_stop_features_sb)
{
    const advsec_feature_type type = ADVSEC_SAFEBROWSING;
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -stop sb null &";
    ULONG expectedSBEnable = 0;
    char *AdvSecuritySBEnabled = "Advsecurity_SafeBrowsing";

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec = (COSA_DATAMODEL_ADVSEC *)malloc(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!(g_pAdvSecAgent->pAdvSec))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSafeBrows = (COSA_DATAMODEL_SB *)malloc(sizeof(COSA_DATAMODEL_SB));
    if (!(g_pAdvSecAgent->pAdvSec->pSafeBrows))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = TRUE;
    g_pAdvSecAgent->bEnable = TRUE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySBEnabled), expectedSBEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecStopFeatures(type));
    EXPECT_EQ(FALSE, g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable);

    free(g_pAdvSecAgent->pAdvSec->pSafeBrows);
    free(g_pAdvSecAgent->pAdvSec);
    free(g_pAdvSecAgent);
}

TEST_F(CcspAdvSecurityDmlTestFixture, ccsp_advsec_stop_features_sf)
{
    const advsec_feature_type type = ADVSEC_SOFTFLOWD;
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -stop null sf &";
    ULONG expectedSFEnable = 0;
    char *AdvSecuritySFEnabled = "Advsecurity_Softflowd";

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec = (COSA_DATAMODEL_ADVSEC *)malloc(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!(g_pAdvSecAgent->pAdvSec))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSoftFlowd = (COSA_DATAMODEL_SOFTFLOWD *)malloc(sizeof(COSA_DATAMODEL_SOFTFLOWD));
    if (!(g_pAdvSecAgent->pAdvSec->pSoftFlowd))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = TRUE;
    g_pAdvSecAgent->bEnable = TRUE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySFEnabled), expectedSFEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecStopFeatures(type));
    EXPECT_EQ(FALSE, g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable);

    free(g_pAdvSecAgent->pAdvSec->pSoftFlowd);
    free(g_pAdvSecAgent->pAdvSec);
    free(g_pAdvSecAgent);
}

TEST_F(CcspAdvSecurityDmlTestFixture, ccsp_advsec_stop_features_sb_sf)
{
    const advsec_feature_type type = ADVSEC_ALL;
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -stop sb sf &";
    ULONG expectedSBSFEnable = 0;
    char *AdvSecuritySBEnabled = "Advsecurity_SafeBrowsing";
    char *AdvSecuritySFEnabled = "Advsecurity_Softflowd";

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec = (COSA_DATAMODEL_ADVSEC *)malloc(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!(g_pAdvSecAgent->pAdvSec))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSoftFlowd = (COSA_DATAMODEL_SOFTFLOWD *)malloc(sizeof(COSA_DATAMODEL_SOFTFLOWD));
    if (!(g_pAdvSecAgent->pAdvSec->pSoftFlowd))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }
    g_pAdvSecAgent->pAdvSec->pSafeBrows = (COSA_DATAMODEL_SB *)malloc(sizeof(COSA_DATAMODEL_SB));
    if (!(g_pAdvSecAgent->pAdvSec->pSafeBrows))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent->pAdvSec->pSoftFlowd);
        free(g_pAdvSecAgent->pAdvSec);
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = TRUE;
    g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = TRUE;
    g_pAdvSecAgent->pAdvSec->bEnable = FALSE;
    g_pAdvSecAgent->bEnable = TRUE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySBEnabled), expectedSBSFEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(AdvSecuritySFEnabled), expectedSBSFEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecStopFeatures(type));
    EXPECT_EQ(FALSE, g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable);
    EXPECT_EQ(FALSE, g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable);

    free(g_pAdvSecAgent->pAdvSec->pSafeBrows);
    free(g_pAdvSecAgent->pAdvSec->pSoftFlowd);
    free(g_pAdvSecAgent->pAdvSec);
    free(g_pAdvSecAgent);
}

TEST_F(CcspAdvSecurityDmlTestFixture, Cosa_AdvSec_Agent_Raptr_Init)
{
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -enableRaptr &";
    ULONG expectedRaptrEnable = 1;
    char *RaptrEnabled = "Adv_RaptrRFCEnable";

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pRaptr_RFC = (COSA_DATAMODEL_RAPTR_RFC *)malloc(sizeof(COSA_DATAMODEL_RAPTR_RFC));
    if (!(g_pAdvSecAgent->pRaptr_RFC))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pRaptr_RFC->bEnable = TRUE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(RaptrEnabled), expectedRaptrEnable))
        .Times(1)
        .WillOnce(Return(ANSC_STATUS_SUCCESS));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecAgentRaptrInit(g_pAdvSecAgent->pRaptr_RFC));
    EXPECT_EQ(TRUE, g_pAdvSecAgent->pRaptr_RFC->bEnable);

    free(g_pAdvSecAgent->pRaptr_RFC);
    free(g_pAdvSecAgent);
}

TEST_F(CcspAdvSecurityDmlTestFixture, Cosa_AdvSec_Agent_Raptr_DeInit)
{
    const std::string cmd = "/usr/ccsp/advsec/start_adv_security.sh -disableRaptr &";
    ULONG expectedRaptrEnable = 0;
    char *RaptrEnabled = "Adv_RaptrRFCEnable";

    g_pAdvSecAgent = (COSA_DATAMODEL_AGENT *)malloc(sizeof(COSA_DATAMODEL_AGENT));
    if (!g_pAdvSecAgent)
    {
        printf("Sorry! unable to allocate memory");
        exit(1);
    }
    g_pAdvSecAgent->pRaptr_RFC = (COSA_DATAMODEL_RAPTR_RFC *)malloc(sizeof(COSA_DATAMODEL_RAPTR_RFC));
    if (!(g_pAdvSecAgent->pRaptr_RFC))
    {
        printf("Sorry! unable to allocate memory");
        free(g_pAdvSecAgent);
        exit(1);
    }

    g_pAdvSecAgent->pRaptr_RFC->bEnable = FALSE;

    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(_))
        .Times(0);
    EXPECT_CALL(*g_AdvsecInternalMock, v_secure_system(StrEq(cmd)))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_AdvsecInternalMock, CosaSetSysCfgUlong(StrEq(RaptrEnabled), expectedRaptrEnable))
       .Times(1)
       .WillOnce(Return(ANSC_STATUS_SUCCESS));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaAdvSecAgentRaptrDeInit(g_pAdvSecAgent->pRaptr_RFC));
    EXPECT_EQ(FALSE, g_pAdvSecAgent->pRaptr_RFC->bEnable);

    free(g_pAdvSecAgent->pRaptr_RFC);
    free(g_pAdvSecAgent);
}