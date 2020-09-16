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
#include "../include/chillbuff.h"

/* A test case that does nothing and succeeds. */
static void null_test_success(void** state)
{
    (void)state;
}

static void Chillbuff_Init_Buff_Arg_NULL_Returns_CHILLBUFF_NULL_ARG(void** state)
{
    assert_int_equal(CHILLBUFF_NULL_ARG, chillbuff_init(NULL, 8, 1, CHILLBUFF_GROW_DUPLICATIVE));
}

static void Chillbuff_Element_Size_0_Returns_CHILLBUFF_INVALID_ARG(void** state)
{
    chillbuff b;
    assert_int_equal(CHILLBUFF_INVALID_ARG, chillbuff_init(&b, 16, 0, CHILLBUFF_GROW_DUPLICATIVE));
}

static void Chillbuff_Element_Invalid_Grow_Method_Returns_CHILLBUFF_INVALID_ARG(void** state)
{
    chillbuff b;
    assert_int_equal(CHILLBUFF_INVALID_ARG, chillbuff_init(&b, 16, 1, -1));
    assert_int_equal(CHILLBUFF_INVALID_ARG, chillbuff_init(&b, 16, 1, 200));
}

static void Chillbuff_Init_Returns_CHILLBUFF_SUCCESS(void** state)
{
    chillbuff b;
    int r = chillbuff_init(&b, 16, 1, CHILLBUFF_GROW_DUPLICATIVE);
    assert_int_equal(CHILLBUFF_SUCCESS, r);
    if (r == CHILLBUFF_SUCCESS)
      chillbuff_free(&b);
}

static void Chillbuff_Push_Back_Buff_Arg_NULL_Returns_CHILLBUFF_NULL_ARG(void** state)
{
    chillbuff b;
    chillbuff_init(&b, 8, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    assert_int_equal(CHILLBUFF_NULL_ARG, chillbuff_push_back(NULL, "test", strlen("test")));
    chillbuff_free(&b);
}

static void Chillbuff_Push_Back_Elements_Arg_NULL_Returns_CHILLBUFF_NULL_ARG(void** state)
{
    chillbuff b;
    chillbuff_init(&b, 8, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    assert_int_equal(CHILLBUFF_NULL_ARG, chillbuff_push_back(&b, NULL, strlen("test")));
    chillbuff_free(&b);
}

static void Chillbuff_Push_Back_Elements_Count_Arg_0_Returns_CHILLBUFF_INVALID_ARG(void** state)
{
    chillbuff b;
    chillbuff_init(&b, 8, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    assert_int_equal(CHILLBUFF_INVALID_ARG, chillbuff_push_back(&b, "test", 0));
    chillbuff_free(&b);
}

static void Chillbuff_Duplicative_Growth_Method_Really_Does_Double_The_Size(void** state)
{
    chillbuff b1;

    chillbuff_init(&b1, 8, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    chillbuff_push_back(&b1, "long string", strlen("long string"));
    assert_int_equal(16, (int)(b1.capacity));
    chillbuff_free(&b1);

    chillbuff b2;

    chillbuff_init(&b2, 8, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
    chillbuff_push_back(&b2, "very long test string", strlen("very long test string"));
    assert_int_equal(32, (int)(b2.capacity));
    chillbuff_free(&b2);
}

static void Chillbuff_Triplicative_Growth_Method_Really_Does_Triple_The_Size(void** state)
{
    chillbuff b1;

    chillbuff_init(&b1, 8, sizeof(char), CHILLBUFF_GROW_TRIPLICATIVE);
    chillbuff_push_back(&b1, "long string", strlen("long string"));
    assert_int_equal(24, (int)(b1.capacity));
    chillbuff_free(&b1);

    chillbuff b2;

    chillbuff_init(&b2, 8, sizeof(char), CHILLBUFF_GROW_TRIPLICATIVE);
    chillbuff_push_back(&b2, "very long test string ...", strlen("very long test string ..."));
    assert_int_equal(72, (int)(b2.capacity));
    chillbuff_free(&b2);
}

static void Chillbuff_Linear_Growth_Method_Really_Does_Append_Same_Element_Size(void** state)
{
    chillbuff b;
    chillbuff_init(&b, 8, sizeof(char), CHILLBUFF_GROW_LINEAR);

    chillbuff_push_back(&b, "long string!", strlen("long string!"));
    assert_int_equal(12, (int)(b.capacity));

    chillbuff_push_back(&b, "teststr", strlen("teststr"));
    assert_int_equal(19, (int)(b.capacity));

    chillbuff_free(&b);
}

static void Chillbuff_Exponential_Growth_Method_Really_Does_Multiply_Size_By_Itself(void** state)
{
    chillbuff b;
    chillbuff_init(&b, 8, sizeof(char), CHILLBUFF_GROW_EXPONENTIAL);

    chillbuff_push_back(&b, "long string", strlen("long string"));
    assert_int_equal(64, (int)(b.capacity));

    chillbuff_push_back(&b, "very very very very very very very very very very long test string", strlen("very very very very very very very very very very long test string"));
    assert_int_equal(4096, (int)(b.capacity));

    chillbuff_free(&b);
}

static void Chillbuff_As_StringBuilder_Concatenates_Strings_Correctly(void** state)
{
    chillbuff b;
    chillbuff_init(&b, 8, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);

    static const char* LIPS[] = 
    {
        "Lorem ip ",
        "sum dolor sick fuck",
        " amet thing thing place",
        "holder in latin blabla ",
        "dId Th3Y eVèn hävE th€sé",
        " $pe%sciaL chAr¨actëR£$ in anC++ienT R0m€ ° ^ ~??"
    };

    chillbuff_push_back(&b, LIPS[0], strlen(LIPS[0]));
    chillbuff_push_back(&b, LIPS[1], strlen(LIPS[1]));
    chillbuff_push_back(&b, LIPS[2], strlen(LIPS[2]));
    chillbuff_push_back(&b, LIPS[3], strlen(LIPS[3]));
    chillbuff_push_back(&b, LIPS[4], strlen(LIPS[4]));
    chillbuff_push_back(&b, LIPS[5], strlen(LIPS[5]));

    assert_string_equal("Lorem ip sum dolor sick fuck amet thing thing placeholder in latin blabla dId Th3Y eVèn hävE th€sé $pe%sciaL chAr¨actëR£$ in anC++ienT R0m€ ° ^ ~??", (char*)b.array);

    chillbuff_free(&b);
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test(null_test_success), 
        cmocka_unit_test(Chillbuff_Init_Buff_Arg_NULL_Returns_CHILLBUFF_NULL_ARG), 
        cmocka_unit_test(Chillbuff_Element_Size_0_Returns_CHILLBUFF_INVALID_ARG), 
        cmocka_unit_test(Chillbuff_Element_Invalid_Grow_Method_Returns_CHILLBUFF_INVALID_ARG), 
        cmocka_unit_test(Chillbuff_Init_Returns_CHILLBUFF_SUCCESS),
        cmocka_unit_test(Chillbuff_Push_Back_Buff_Arg_NULL_Returns_CHILLBUFF_NULL_ARG),
        cmocka_unit_test(Chillbuff_Push_Back_Elements_Arg_NULL_Returns_CHILLBUFF_NULL_ARG),
        cmocka_unit_test(Chillbuff_Push_Back_Elements_Count_Arg_0_Returns_CHILLBUFF_INVALID_ARG),
        cmocka_unit_test(Chillbuff_Duplicative_Growth_Method_Really_Does_Double_The_Size),
        cmocka_unit_test(Chillbuff_Triplicative_Growth_Method_Really_Does_Triple_The_Size),
        cmocka_unit_test(Chillbuff_Linear_Growth_Method_Really_Does_Append_Same_Element_Size),
        cmocka_unit_test(Chillbuff_Exponential_Growth_Method_Really_Does_Multiply_Size_By_Itself),
        cmocka_unit_test(Chillbuff_As_StringBuilder_Concatenates_Strings_Correctly),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
