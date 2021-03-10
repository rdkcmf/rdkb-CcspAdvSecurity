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

#include <errno.h>
#include <string.h>
#include <msgpack.h>
#include "ccsp_trace.h"
#include "advsecurity_helpers.h"
#include "safec_lib_common.h"
/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
/* none */
/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
/* none */
/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
/* none */
/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
msgpack_object* __finder_comp( const char *name, 
                          msgpack_object_type expect_type,
                          msgpack_object_map *map );
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
void* comp_helper_convert( const void *buf, size_t len,
                      size_t struct_size, const char *wrapper,
                      msgpack_object_type expect_type, bool optional,
                      process_fn_t process,
                      destroy_fn_t destroy )
{
    errno_t rc = -1;
    int ind = -1;
    void *p = malloc( struct_size );
    if( NULL == p )
    {
        errno = HELPERS_OUT_OF_MEMORY;
    }
    else
    {
        rc = memset_s( p, struct_size, 0, struct_size );
        ERR_CHK(rc);
        if( NULL != buf && 0 < len )
        {
            size_t offset = 0;
            msgpack_unpacked msg;
            msgpack_unpack_return mp_rv;
            msgpack_unpacked_init( &msg );
            /* The outermost wrapper MUST be a map. */
            mp_rv = msgpack_unpack_next( &msg, (const char*) buf, len, &offset );
	/*For Printing the msgpack object use the following 3 lines*/
	    msgpack_object obj = msg.data;
            msgpack_object_print(stdout, obj);
            fprintf(stderr,"\n");

            if( (MSGPACK_UNPACK_SUCCESS == mp_rv) && (0 != offset) &&
                (MSGPACK_OBJECT_MAP == msg.data.type) )
            {
                msgpack_object *inner;
                msgpack_object *subdoc_name;
                msgpack_object *version;
                msgpack_object *transaction_id;
                
                if(NULL != wrapper)
                {
                    rc = strcmp_s("parameters", strlen("parameters"), wrapper, &ind);
                    ERR_CHK(rc);
                    if((rc == EOK) && (ind == 0))
                    {
                        inner = __finder_comp( wrapper, expect_type, &msg.data.via.map );
                    
                        if( ((NULL != inner) && (0 == (process)(p, 1, inner))) ||
                              ((true == optional) && (NULL == inner)) )
                        {
                            msgpack_unpacked_destroy( &msg );
                            errno = HELPERS_OK;
                            return p;
                        }
                        else
                        {
                            errno = HELPERS_INVALID_FIRST_ELEMENT;
                        }
                    }
                    else if((rc == EOK) && (ind != 0))
                    {
                        inner = __finder_comp( wrapper, expect_type, &msg.data.via.map );
                        subdoc_name =  __finder_comp( "subdoc_name", expect_type, &msg.data.via.map );
                        version =  __finder_comp( "version", expect_type, &msg.data.via.map );
                        transaction_id =  __finder_comp( "transaction_id", expect_type, &msg.data.via.map );
                    
                        if( ((NULL != inner) && (0 == (process)(p,4, inner, subdoc_name, version, transaction_id))) ||
                              ((true == optional) && (NULL == inner)) )
                        {
                            msgpack_unpacked_destroy( &msg );
                            errno = HELPERS_OK;
                            return p;
                        }
                        else 
                        {      
                            CcspTraceWarning(("%s Invalid first element\n", __FUNCTION__));
                            errno = HELPERS_INVALID_FIRST_ELEMENT;
                        }
                   }
                }
              }
            msgpack_unpacked_destroy( &msg );
            if(NULL!=p)
            {
               (destroy)( p );
                p = NULL;
            }
            
        }
    }
    return p;
}
/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

//Used to find the map object using the key 

msgpack_object* __finder_comp( const char *name, 
                          msgpack_object_type expect_type,
                          msgpack_object_map *map )
{
    uint32_t i;

    if(name == NULL)
        return NULL;


    for( i = 0; i < map->size; i++ ) 
    {
	

        if( MSGPACK_OBJECT_STR == map->ptr[i].key.type ) 
        {
            if( expect_type == map->ptr[i].val.type ) 
            {
                if( 0 == match(&(map->ptr[i]), name) ) 
                {
                    return &map->ptr[i].val;
                }
            }
            else 
            {
                if(0 == strncmp(map->ptr[i].key.via.str.ptr, name, strlen(name)))
                {   
                    return &map->ptr[i].val;
                }
                
             }
            }
        }
	CcspTraceWarning(("%s The wrapper %s is missing\n", __FUNCTION__, name));
     errno = HELPERS_MISSING_WRAPPER;
    return NULL;
}

