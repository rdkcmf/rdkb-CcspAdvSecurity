#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 512

int CujoCloudConnectivity(char const* str)
{
    char buff[BUFFER_SIZE];
    memset(buff, 0, sizeof(buff));
    char value[32] = "200";
    FILE * fp = popen( str, "r" );
    if ( fp == NULL )
    {
        return -1;
    }

    fgets(buff, sizeof(buff), fp);
    pclose(fp);

    if (strncmp(buff,value,strlen(value)) == 0)
    {
       return 0;
    }
    else
    {
       return 1;
    }
}

int CujoAgentProcessStatus(char const* str)
{
    char buff[BUFFER_SIZE];
    memset(buff, 0, sizeof(buff));
    char value[32] = "1";
    FILE * fp = popen( str, "r" );
    if ( fp == NULL )
    {
        return -1;
    }

    fgets(buff, sizeof(buff), fp);
    pclose(fp);

    if (strncmp(buff,value,strlen(value)) == 0)
    {
       return 0;
    }
    else
    {
       return 1;
    }
}

int CcspAdvsecProcessStatus(char const* str)
{
    char buff[BUFFER_SIZE];
    memset(buff, 0, sizeof(buff));
    char value[32] = "1";
    FILE * fp = popen( str, "r" );
    if ( fp == NULL )
    {
        return -1;
    }

    fgets(buff, sizeof(buff), fp);
    pclose(fp);

    if (strncmp(buff,value,strlen(value)) == 0)
    {
       return 0;
    }
    else
    {
       return 1;
    }
}

int CcspAdvsecFeatureTr181(char const* str)
{
    char buff[BUFFER_SIZE];
    memset(buff, 0, sizeof(buff));
    char value[32] = "true";
    FILE * fp = popen( str, "r" );
    if ( fp == NULL )
    {
        return -1;
    }

    fgets(buff, sizeof(buff), fp);
    pclose(fp);

    if (strncmp(buff,value,strlen(value)) == 0)
    {
       return 0;
    }
    else
    {
       return 1;
    }
}