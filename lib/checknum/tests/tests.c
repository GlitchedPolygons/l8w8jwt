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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../include/checknum.h"

static void null_test_success(void** state)
{
    (void)state;
}

static void test_zeros(void** state)
{
    assert_int_equal(checknum("0.00000", 0), 2);
    assert_int_equal(checknum("0", 0), 1);
    assert_int_equal(checknum("00", 0), 0);
    assert_int_equal(checknum("0  ", 0), 1);
    assert_int_equal(checknum("  0", 0), 1);
    assert_int_equal(checknum("  0  ", 0), 1);
    assert_int_equal(checknum(" 0123", 0), 0);
    assert_int_equal(checknum(".0 ", 0), 2);
    assert_int_equal(checknum(".00", 0), 2);
    assert_int_equal(checknum(" .   ", 0), 0);
    assert_int_equal(checknum("0.", 0), 2);
    assert_int_equal(checknum("+.", 0), 0);
    assert_int_equal(checknum("-.   ", 0), 0);
}

static void test_integers(void** state)
{
    assert_int_equal(checknum("420", 0), 1);
    assert_int_equal(checknum("941L", 0), 0);
    assert_int_equal(checknum("0666", 0), 0);
    assert_int_equal(checknum("-42", 0), 1);
    assert_int_equal(checknum("-42-", 0), 0);
    assert_int_equal(checknum("--42", 0), 0);
    assert_int_equal(checknum("-+42", 0), 0);
    assert_int_equal(checknum("+42", 0), 1);
    assert_int_equal(checknum("++42", 0), 0);
    assert_int_equal(checknum("+ 42", 0), 0);
    assert_int_equal(checknum("- 42", 0), 0);
    assert_int_equal(checknum("   1337 ", 1), 0);
    assert_int_equal(checknum("4256337 ", 0), 1);
    assert_int_equal(checknum("fdfdx5865jnw", 0), 0);
    assert_int_equal(checknum("-54141375154", 0), 1);
    assert_int_equal(checknum(" +9946731546733", 0), 1);
}

static void test_floats(void** state)
{
    assert_int_equal(checknum(" 1337.420    ", 0), 2);
    assert_int_equal(checknum(".2579000   ", 0), 2);
    assert_int_equal(checknum("  0.04e-9000", 0), 2);
    assert_int_equal(checknum(" 42.01E+92  ", 0), 2);
    assert_int_equal(checknum("  .0 ", 0), 2);
    assert_int_equal(checknum(" .2E-3   ", 0), 2);
    assert_int_equal(checknum(".2E-3", 0), 2);
    assert_int_equal(checknum("   .2E-32 ", 0), 2);
    assert_int_equal(checknum(".7E", 0), 0);
    assert_int_equal(checknum(" .       ", 0), 0);
    assert_int_equal(checknum("0.       ", 0), 2);
    assert_int_equal(checknum("7.       ", 0), 2);
    assert_int_equal(checknum("+.       ", 0), 0);
    assert_int_equal(checknum("-.       ", 0), 0);
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(test_zeros),
        cmocka_unit_test(test_floats),
        cmocka_unit_test(test_integers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
