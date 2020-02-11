[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e61f74e564154b669f4b0d48328364c6)](https://www.codacy.com/manual/GlitchedPolygons/checknum?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/checknum&amp;utm_campaign=Badge_Grade)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/ffxu9yrkm5dgkknm?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/checknum)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/checknum/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/checknum/tree/master)
[![SHO Shield](https://img.shields.io/badge/single-header--only-blue)](https://github.com/GlitchedPolygons/checknum/blob/master/checknum.h)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/l8w8jwt/blob/master/LICENSE)

# Checknum
### Check whether a given C-string contains an integer or a floating-point number.

This is really more of a snippet than anything else. Feel free to (ab)use this as much as you want.

### Usage:

```C
#include "checknum.h"

int main(void) {

  int r = checknum(some_NUL_terminated_c_string, strlen(some_NUL_terminated_c_string));

  switch (r) {
    case 0:
    default:
      // Not a valid number...
      break;
    case 1:
      // The string contains an integer.
      break;
    case 2:
      // The string contains a floating-point number.
      break;
  }
}
```
