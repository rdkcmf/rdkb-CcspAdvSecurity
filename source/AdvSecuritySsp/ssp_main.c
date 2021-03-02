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

#ifdef __GNUC__
#if (!defined _NO_EXECINFO_H_)
#include <execinfo.h>
#endif
#endif

#include "ssp_global.h"
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
#include "stdlib.h"
#include "webconfig_framework.h"

#define MAX_SUBSYSTEM_SIZE 32

#define ADVSEC_CCSP_INIT_FILE_BOOTUP "/tmp/advsec_ccsp_initialized_bootup"

PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController      = NULL;
PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm  = NULL;
PCCSP_FC_CONTEXT                pAdvSecFcContext           = (PCCSP_FC_CONTEXT            )NULL;
PCCSP_CCD_INTERFACE             pAdvSecCcdIf               = (PCCSP_CCD_INTERFACE         )NULL;
PCCC_MBI_INTERFACE              pTadMbiIf               = (PCCC_MBI_INTERFACE          )NULL;
char                            g_Subsystem[MAX_SUBSYSTEM_SIZE]         = {0};
BOOL                            g_bActive               = FALSE;

int consoleDebugEnable = 0;
FILE* debugLogFile;

int  cmd_dispatch(int  command)
{
    char*                           pParamNames[]      = {"Device.IP.Diagnostics.IPPing."};
    parameterValStruct_t**          ppReturnVal        = NULL;
    int                             ulReturnValCount   = 0;
    int                             i                  = 0;

    switch ( command )
    {
            case	'e' :

#ifdef _ANSC_LINUX
                CcspTraceInfo(("Connect to bus daemon...\n"));

            {
                char                            CName[256];

                if ( g_Subsystem[0] != 0 )
                {
                    _ansc_sprintf(CName, "%s%s", g_Subsystem, CCSP_COMPONENT_ID_ADVSEC);
                }
                else
                {
                    _ansc_sprintf(CName, "%s", CCSP_COMPONENT_ID_ADVSEC);
                }

                ssp_AdvsecMbi_MessageBusEngage
                    ( 
                        CName,
                        CCSP_MSG_BUS_CFG,
                        CCSP_COMPONENT_PATH_ADVSEC
                    );
            }

#endif

                ssp_create_advsec();
                ssp_engage_advsec();
                g_bActive = TRUE;

                CcspTraceInfo(("AdvSec Module loaded successfully...\n"));

            break;

            case    'r' :

            CcspCcMbi_GetParameterValues
                (
                    DSLH_MPA_ACCESS_CONTROL_ACS,
                    pParamNames,
                    1,
                    &ulReturnValCount,
                    &ppReturnVal,
                    NULL
                );



            for ( i = 0; i < ulReturnValCount; i++ )
            {
                CcspTraceWarning(("Parameter %d name: %s value: %s \n", i+1, ppReturnVal[i]->parameterName, ppReturnVal[i]->parameterValue));
            }

			break;

        case    'm':

                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':

                AnscTraceMemoryTable();

                break;

        case    'c':

                ssp_cancel_advsec();

                break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#if (!defined _COSA_SIM_) && (!defined _NO_EXECINFO_H_)
        void* tracePtrs[100];
        char** funcNames = NULL;
        int i, count = 0;

        int fd;
        const char* path = "/nvram/advsecssp_backtrace";
        fd = open(path, O_RDWR | O_CREAT);
        if (fd < 0)
        {
            CcspTraceError(("failed to open backtrace file: %s", path));
            return;
        }

        count = backtrace( tracePtrs, 100 );
        backtrace_symbols_fd( tracePtrs, count, fd );
        close(fd);

        funcNames = backtrace_symbols( tracePtrs, count );

        if ( funcNames ) {
            // Print the stack trace
            for( i = 0; i < count; i++ )
                CcspTraceInfo(("%s\n", funcNames[i] ));

            // Free the string pointers
            free( funcNames );
        }
#endif
#endif
}

#if defined(_ANSC_LINUX)
static void daemonize(void) {
	switch (fork()) {
	case 0:
		break;
	case -1:
		// Error
		CcspTraceError(("Error daemonizing (fork)! %d - %s\n", errno, strerror(
				errno)));
		exit(0);
		break;
	default:
		_exit(0);
	}

	if (setsid() < 	0) {
		CcspTraceError(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
		exit(0);
	}

//	chdir("/");


#ifndef  _DEBUG

	int fd;
	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT ) {
    	signal(SIGINT, sig_handler); /* reset it to this function */
    	CcspTraceError(("SIGINT received!\n"));
        exit(0);
    }
    else if ( sig == SIGUSR1 ) {
    	signal(SIGUSR1, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 ) {
    	CcspTraceWarning(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD ) {
    	signal(SIGCHLD, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE ) {
    	signal(SIGPIPE, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGPIPE received!\n"));
    }
    else {
    	/* get stack trace first */
    	_print_stack_backtrace();
    	CcspTraceError(("Signal %d received, exiting!\n", sig));
    	exit(0);
    }

}

#endif

int main(int argc, char* argv[])
{
    int                             cmdChar            = 0;
    BOOL                            bRunAsDaemon       = TRUE;
    int                             idx                = 0;
    debugLogFile = stderr;
#if defined(_DEBUG) && defined(_COSA_SIM_)
    AnscSetTraceLevel(CCSP_TRACE_LEVEL_INFO);
#endif

    for (idx = 1; idx < argc; idx++)
    {
        if ( (strcmp(argv[idx], "-subsys") == 0) )
        {
          /* Coverity Fix  CID:135431 STRING_SIZE */
            if( ( (idx+1) < argc  ) && ( strlen(argv[idx + 1]) < sizeof(g_Subsystem) ) )
            {
              AnscCopyString(g_Subsystem, argv[idx+1]);
            }
            else
            {
              CcspTraceWarning(("idx + 1 exceeds argc  \n"));  
              exit(0);
            }
                      
        }
        else if ( strcmp(argv[idx], "-c") == 0 )
        {
            bRunAsDaemon = FALSE;
        }
        else if ( (strcmp(argv[idx], "-DEBUG") == 0) )
        {
            consoleDebugEnable = 1;
            CcspTraceInfo(("DEBUG ENABLE ON \n"));
        }
        else if ( (strcmp(argv[idx], "-LOGFILE") == 0) )
        {
            // We assume argv[1] is a filename to open
            debugLogFile = fopen( argv[idx + 1], "a+" );

            /* fopen returns 0, the NULL pointer, on failure */
            if ( debugLogFile == 0 )
            {
                debugLogFile = stderr;
                CcspTraceWarning(("Invalid Entry for -LOGFILE input \n"));
            }
            else 
            {
                fprintf(debugLogFile, "Log File [%s] Opened for Writing in Append Mode \n",  argv[idx+1]);
            }

        }          
    }

    /* Set the global pComponentName */
    pComponentName = CCSP_COMPONENT_NAME_ADVSEC;

#ifdef   _DEBUG
    /*AnscSetTraceLevel(CCSP_TRACE_LEVEL_INFO);*/
#endif

#if  defined(_ANSC_WINDOWSNT)

    AnscStartupSocketWrapper(NULL);

    display_info();

    cmd_dispatch('e');

    while ( cmdChar != 'q' )
    {
        cmdChar = getchar();

        cmd_dispatch(cmdChar);
    }
#elif defined(_ANSC_LINUX)
    if ( bRunAsDaemon )
        daemonize();

#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#else
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGPIPE, SIG_IGN);
#endif

    cmd_dispatch('e');

    check_component_crash(ADVSEC_CCSP_INIT_FILE_BOOTUP);

    CcspTraceInfo(("ADVSEC:----------------------touch /tmp/advsec_ccsp__initialized_bootup-------------------\n"));
    char init_file[128] = {0};
    snprintf(init_file,sizeof(init_file),"touch %s",ADVSEC_CCSP_INIT_FILE_BOOTUP);
    system(init_file);

    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            sleep(30);
            cmd_dispatch(cmdChar);
        }
    }
#endif

    if ( g_bActive )
    {
        ssp_cancel_advsec();

        g_bActive = FALSE;
    }

    return 0;
}


