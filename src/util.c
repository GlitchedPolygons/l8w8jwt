/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "l8w8jwt/util.h"
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

int l8w8jwt_hexstr2bin(const char* hexstr, const size_t hexstr_length, unsigned char* output, const size_t output_size, size_t* output_length)
{
    if (hexstr == NULL || output == NULL || hexstr_length == 0)
    {
        return 1;
    }

    const size_t hl = hexstr[hexstr_length - 1] ? hexstr_length : hexstr_length - 1;

    if (hl % 2 != 0)
    {
        return 2;
    }

    const size_t final_length = hl / 2;

    if (output_size < final_length + 1)
    {
        return 3;
    }

    for (size_t i = 0, ii = 0; ii < final_length; i += 2, ++ii)
    {
        output[ii] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

int l8w8jwt_strncmpic(const char* str1, const char* str2, size_t n)
{
    size_t cmp = 0;
    int ret = -1;

    if (str1 == NULL || str2 == NULL)
    {
        return ret;
    }

    while ((*str1 || *str2) && cmp < n)
    {
        if ((ret = tolower((int)(*str1)) - tolower((int)(*str2))) != 0)
        {
            break;
        }

        cmp++;
        str1++;
        str2++;
    }

    return ret;
}

// https://github.com/GlitchedPolygons/l8w8jwt/issues/50
// Thanks @BrunoVernay for submitting the issue and making me notice the CVE-2024-25190.
// Thanks @chmike for the cst_time_memcmp implementation from which below code was taken: https://github.com/chmike/cst_time_memcmp/blob/master/consttime_memcmp.c

int l8w8jwt_memcmp(const void* mem1, const void* mem2, size_t n)
{
    const unsigned char *c1, *c2;
    unsigned short d, r, m;

#if USE_VOLATILE_TEMPORARY
    volatile unsigned short v;
#else
    unsigned short v;
#endif

    c1 = mem1;
    c2 = mem2;

    r = 0;
    while (n)
    {
        /*
         * Take the low 8 bits of r (in the range 0x00 to 0xff,
         * or 0 to 255);
         * As explained elsewhere, the low 8 bits of r will be zero
         * if and only if all bytes compared so far were identical;
         * Zero-extend to a 16-bit type (in the range 0x0000 to
         * 0x00ff);
         * Add 255, yielding a result in the range 255 to 510;
         * Save that in a volatile variable to prevent
         * the compiler from trying any shortcuts (the
         * use of a volatile variable depends on "#ifdef
         * USE_VOLATILE_TEMPORARY", and most compilers won't
         * need it);
         * Divide by 256 yielding a result of 1 if the original
         * value of r was non-zero, or 0 if r was zero;
         * Subtract 1, yielding 0 if r was non-zero, or -1 if r
         * was zero;
         * Convert to unsigned short, yielding 0x0000 if r was
         * non-zero, or 0xffff if r was zero;
         * Save in m.
         */
        v = ((unsigned short)(unsigned char)r) + 255;
        m = v / 256 - 1;

        /*
         * Get the values from *c1 and *c2 as unsigned char (each will
         * be in the range 0 to 255, or 0x00 to 0xff);
         * Convert them to signed int values (still in the
         * range 0 to 255);
         * Subtract them using signed arithmetic, yielding a
         * result in the range -255 to +255;
         * Convert to unsigned short, yielding a result in the range
         * 0xff01 to 0xffff (for what was previously -255 to
         * -1), or 0, or in the range 0x0001 to 0x00ff (for what
         * was previously +1 to +255).
         */
        d = (unsigned short)((int)*c1 - (int)*c2);

        /*
         * If the low 8 bits of r were previously 0, then m
         * is now 0xffff, so (d & m) is the same as d, so we
         * effectively copy d to r;
         * Otherwise, if r was previously non-zero, then m is
         * now 0, so (d & m) is zero, so leave r unchanged.
         * Note that the low 8 bits of d will be zero if and
         * only if d == 0, which happens when *c1 == *c2.
         * The low 8 bits of r are thus zero if and only if the
         * entirety of r is zero, which happens if and only if
         * all bytes compared so far were equal.  As soon as a
         * non-zero value is stored in r, it remains unchanged
         * for the remainder of the loop.
         */
        r |= (d & m);

        /*
         * Increment pointers, decrement length, and loop.
         */
        ++c1;
        ++c2;
        --n;
    }

    /*
     * At this point, r is an unsigned value, which will be 0 if the
     * final result should be zero, or in the range 0x0001 to 0x00ff
     * (1 to 255) if the final result should be positive, or in the
     * range 0xff01 to 0xffff (65281 to 65535) if the final result
     * should be negative.
     *
     * We want to convert the unsigned values in the range 0xff01
     * to 0xffff to signed values in the range -255 to -1, while
     * converting the other unsigned values to equivalent signed
     * values (0, or +1 to +255).
     *
     * On a machine with two's complement arithmetic, simply copying
     * the underlying bits (with sign extension if int is wider than
     * 16 bits) would do the job, so something like this might work:
     *
     *     return (int16_t)r;
     *
     * However, that invokes implementation-defined behaviour,
     * because values larger than 32767 can't fit in a signed 16-bit
     * integer without overflow.
     *
     * To avoid any implementation-defined behaviour, we go through
     * these contortions:
     *
     * a. Calculate ((uint32_t)r + 0x8000).  The cast to uint32_t
     *    it to prevent problems on platforms where int is narrower
     *    than 32 bits.  If int is a larger than 32-bits, then the
     *    usual arithmetic conversions cause this addition to be
     *    done in unsigned int arithmetic.  If int is 32 bits
     *    or narrower, then this addition is done in uint32_t
     *    arithmetic.  In either case, no overflow or wraparound
     *    occurs, and the result from this step has a value that
     *    will be one of 0x00008000 (32768), or in the range
     *    0x00008001 to 0x000080ff (32769 to 33023), or in the range
     *    0x00017f01 to 0x00017fff (98049 to 98303).
     *
     * b. Cast the result from (a) to unsigned short.  This effectively
     *    discards the high bits of the result, in a way that is
     *    well defined by the C language.  The result from this step
     *    will be of type unsigned short, and its value will be one of
     *    0x8000 (32768), or in the range 0x8001 to 0x80ff (32769 to
     *    33023), or in the range 0x7f01 to 0x7fff (32513 to
     *    32767).
     *
     * c. Cast the result from (b) to int32_t.  We use int32_t
     *    instead of int because we need a type that's strictly
     *    larger than 16 bits, and the C standard allows
     *    implementations where int is only 16 bits.  The result
     *    from this step will be of type int32_t, and its value wll
     *    be one of 0x00008000 (32768), or in the range 0x00008001
     *    to 0x000080ff (32769 to 33023), or in the range 0x00007f01
     *    to 0x00007fff (32513 to 32767).
     *
     * d. Take the result from (c) and subtract 0x8000 (32768) using
     *    signed int32_t arithmetic.  The result from this step will
     *    be of type int32_t and the value will be one of
     *    0x00000000 (0), or in the range 0x00000001 to 0x000000ff
     *    (+1 to +255), or in the range 0xffffff01 to 0xffffffff
     *    (-255 to -1).
     *
     * e. Cast the result from (d) to int.  This does nothing
     *    interesting, except to make explicit what would have been
     *    implicit in the return statement.  The final result is an
     *    int in the range -255 to +255.
     *
     * Unfortunately, compilers don't seem to be good at figuring
     * out that most of this can be optimised away by careful choice
     * of register width and sign extension.
     *
     */
    return (/*e*/ int)(/*d*/
        (/*c*/ int32_t)(/*b*/ unsigned short)(/*a*/ (unsigned int)r + 0x8000) - 0x8000);
}

#ifdef __cplusplus
} // extern "C"
#endif