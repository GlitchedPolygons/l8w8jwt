/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*

The above mentioned README can be found under:  http://web.mit.edu/freebsd/head/contrib/wpa/

Here's a full paste of it (18. January 2020), in case the URL goes numb:

wpa_supplicant and hostapd
--------------------------

Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi> and contributors
All Rights Reserved.

These programs are licensed under the BSD license (the one with
advertisement clause removed).

If you are submitting changes to the project, please see CONTRIBUTIONS
file for more instructions.


This package may include either wpa_supplicant, hostapd, or both. See
README file respective subdirectories (wpa_supplicant/README or
hostapd/README) for more details.

Source code files were moved around in v0.6.x releases and compared to
earlier releases, the programs are now built by first going to a
subdirectory (wpa_supplicant or hostapd) and creating build
configuration (.config) and running 'make' there (for Linux/BSD/cygwin
builds).


License
-------

This software may be distributed, used, and modified under the terms of
BSD license:

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name(s) of the above-listed copyright holder(s) nor the
   names of its contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/*

http://web.mit.edu/freebsd/head/contrib/wpa/COPYING  (at the time of writing, 18. January 2020)

wpa_supplicant and hostapd
--------------------------

Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi> and contributors
All Rights Reserved.


See the README file for the current license terms.

This software was previously distributed under BSD/GPL v2 dual license
terms that allowed either of those license alternatives to be
selected. As of February 11, 2012, the project has chosen to use only
the BSD license option for future distribution. As such, the GPL v2
license option is no longer used. It should be noted that the BSD
license option (the one with advertisement clause removed) is compatible
with GPL and as such, does not prevent use of this software in projects
that use GPL.

Some of the files may still include pointers to GPL version 2 license
terms. However, such copyright and license notifications are maintained
only for attribution purposes and any distribution of this software
after February 11, 2012 is no longer under the GPL v2 option.

*/

#include <stdio.h>
#include <stdlib.h>
#include "l8w8jwt/base64.h"
#include "l8w8jwt/printferr.h"

static const uint8_t TABLE[64 + 1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const uint8_t URL_SAFE_TABLE[64 + 1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

char* l8w8jwt_base64_encode(const bool url, const uint8_t* data, const size_t data_length, size_t* out_length)
{
    if (data == NULL || data_length == 0)
    {
        l8w8jwt_printferr("The \"data\" input buffer was NULL or empty; nothing to encode!");
        return NULL;
    }

    if (out_length == NULL)
    {
        l8w8jwt_printferr("The \"out_length\" pointer parameter is NULL; please provide something to write the output length into.");
        return NULL;
    }

    uint8_t* out;
    uint8_t* pos;
    const uint8_t* in;
    const uint8_t* end;

    size_t olen = data_length * 4 / 3 + 4;

    olen += olen / 72;
    olen++;

    if (olen < data_length)
    {
        l8w8jwt_printferr("Integer overflow!");
        return NULL;
    }

    out = malloc(olen);
    if (out == NULL)
    {
        l8w8jwt_printferr("Allocation failed - out of memory!");
        return NULL;
    }

    in = data;
    pos = out;
    end = data + data_length;

    int line_length = 0;
    const uint8_t* table = url ? URL_SAFE_TABLE : TABLE;

    while (end - in >= 3)
    {
        *pos++ = table[in[0] >> 2];
        *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = table[in[2] & 0x3f];

        in += 3;

        line_length += 4;
        if (line_length >= 72)
        {
            *pos++ = '\n';
            line_length = 0;
        }
    }

    if (end - in)
    {
        *pos++ = table[in[0] >> 2];

        if (end - in == 1)
        {
            *pos++ = table[(in[0] & 0x03) << 4];
            *pos++ = url ? '\0' : '=';
        }
        else
        {
            *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = table[(in[1] & 0x0f) << 2];
        }

        *pos++ = url ? '\0' : '=';
        line_length += 4;
    }

    if (line_length)
    {
        *pos++ = '\n';
    }

    *pos = '\0';
    *out_length = pos - out;

    return (char*)out;
}

uint8_t* l8w8jwt_base64_decode(const bool url, const char* data, size_t data_length, size_t* out_length)
{
    if (data == NULL || data_length == 0)
    {
        l8w8jwt_printferr("The \"data\" parameter is NULL; nothing to decode!");
        return NULL;
    }

    if (out_length == NULL)
    {
        l8w8jwt_printferr("The \"out_length\" parameter is NULL! Please pass a pointer to write the output buffer's length into.");
        return NULL;
    }

    if (*(data + data_length - 1) == '\0')
    {
        data_length--;
    }

    size_t i;
    uint8_t dtable[256], *out, *pos, block[4], tmp;
    const uint8_t* table = url ? URL_SAFE_TABLE : TABLE;

    memset(dtable, 0x80, 256);
    for (i = 0; i < sizeof(TABLE) - 1; i++)
    {
        dtable[table[i]] = (uint8_t)i;
    }

    dtable['='] = 0;
    size_t count = 0;

    for (i = 0; i < data_length; i++)
    {
        if (dtable[data[i]] != 0x80)
            count++;
    }

    if (count == 0 || count % 4)
        return NULL;

    size_t olen = count / 4 * 3;
    pos = out = malloc(olen + 1);

    if (out == NULL)
    {
        l8w8jwt_printferr("Allocation failed - out of memory!");
        return NULL;
    }

    count = 0;
    int pad = 0;

    for (i = 0; i < data_length; i++)
    {
        tmp = dtable[data[i]];

        if (tmp == 0x80)
            continue;

        if (data[i] == '=')
            pad++;

        block[count] = tmp;
        count++;

        if (count == 4)
        {
            *pos++ = (block[0] << 2) | (block[1] >> 4);
            *pos++ = (block[1] << 4) | (block[2] >> 2);
            *pos++ = (block[2] << 6) | block[3];
            count = 0;
            if (pad)
            {
                if (pad == 1)
                {
                    pos--;
                }
                else if (pad == 2)
                {
                    pos -= 2;
                }
                else
                {
                    l8w8jwt_printferr("Invalid padding!");
                    free(out);
                    return NULL;
                }
                break;
            }
        }
    }

    *out_length = pos - out;
    *pos = '\0';

    return out;
}

/*
 * All credits for this base-64 encoding/decoding implementation go to Jouni Malinen.
 * I take no credit for this (not even the modifications I made to it!) whatsoever.
 * More information at the top of this file.
 */
