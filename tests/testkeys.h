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

static const char ES256_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MHcCAQEEILvM6E7mLOdndALDyFc3sOgUTb6iVjgwRBtBwYZngSuwoAoGCCqGSM49\n"
                                        "AwEHoUQDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBkNGyQ+P4bc/RmNEq1NpsogiMB\n"
                                        "5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ES256_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMlFGAIxe+/zLanxz4bOxTI6daFBk\n"
                                       "NGyQ+P4bc/RmNEq1NpsogiMB5eXC7jUcD/XqxP9HCIhdRBcQHx7aOo3ayQ==\n"
                                       "-----END PUBLIC KEY-----";

static const char ES384_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MIGkAgEBBDCmT7i4o8x5NZDT2nk1D4TUxKDknyx9xGL3F0eRATDndq6MNVmkdAwl\n"
                                        "+8BaWL6xAS6gBwYFK4EEACKhZANiAASmzsk7PEHrovqP3HvWz3lRKpWM0lv//O2A\n"
                                        "wz20beljIJkKCRQiM9K4rlCcdipGwrIj/tlkBWXwbfwuLvZfkJ0SNYtUuC8H/7eu\n"
                                        "UuHfD70y0lfVQ5Ubze5luZ56j+FK+VI=\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ES384_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEps7JOzxB66L6j9x71s95USqVjNJb//zt\n"
                                       "gMM9tG3pYyCZCgkUIjPSuK5QnHYqRsKyI/7ZZAVl8G38Li72X5CdEjWLVLgvB/+3\n"
                                       "rlLh3w+9MtJX1UOVG83uZbmeeo/hSvlS\n"
                                       "-----END PUBLIC KEY-----";

static const char ES512_PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                        "MIHcAgEBBEIA99ixxKKzlE5YmWEq65ZNt6JNXbYkj1x5RrePENwo7oyBNh6v1bHL\n"
                                        "maMyT+dIGVxKXN09x7WeipdArELA891BGeWgBwYFK4EEACOhgYkDgYYABAA3XwC+\n"
                                        "Vf5yIWfKmAdUPkKOpjlklo3pijqsy7r6wnwaUQszopgv5sNxFXNt647L8lZU1KFh\n"
                                        "xFwn2GyXaoEOebcMVgGUhRURpcADMIyVgKEoZcKwjydKDNy40XLKbb4Gzv3LAwpY\n"
                                        "Os+OHwhkHmNGJ9mHIlKzpIaLSiNXwGa1ZosgwPlI6A==\n"
                                        "-----END EC PRIVATE KEY-----";

static const char ES512_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAN18AvlX+ciFnypgHVD5CjqY5ZJaN\n"
                                       "6Yo6rMu6+sJ8GlELM6KYL+bDcRVzbeuOy/JWVNShYcRcJ9hsl2qBDnm3DFYBlIUV\n"
                                       "EaXAAzCMlYChKGXCsI8nSgzcuNFyym2+Bs79ywMKWDrPjh8IZB5jRifZhyJSs6SG\n"
                                       "i0ojV8BmtWaLIMD5SOg=\n"
                                       "-----END PUBLIC KEY-----";

static const char RSA_PRIVATE_KEY[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                                      "MIIJJwIBAAKCAgEAoWFe7BbX1nWo5oaSv/JvIUCWsk/Vi2q8P0cGkefgN5J7MN7K\n"
                                      "fv7lq0hl/1cZcJs81IC+GiC+V3aR2zLBNnJJaxa4sqk+hF5DJcD2bF0B80uqPYQU\n"
                                      "XlQwki/heATnVcke8APuY0kOZykxoD0APAqw0z5KDqgt2vA9G6keM6b9bbL+IvxM\n"
                                      "+yMk1QV0OQLh6Rkz46DyPSoUFWyXiist47PJKNyZAfFZx6vEivzBmqRHKe11W9oD\n"
                                      "/tN5VTQCH/UTSRfyWq/UUMFVMCksLwT6XoWI7F5swgQkSahWkVJ93Qf8cUf1HIZY\n"
                                      "TMJBYPG4y2NDZ0+ytnH3BNXLMQXg9xbgv6B/iaSVScI4CWIpQTAtNKnJwYg2+Rhf\n"
                                      "YBC07iM56c4a+TjbCWgmd11UYc96dbw83uFRjKZc3+SC38ITCgMuoDPNBlFJK6u8\n"
                                      "VfYylGEJolGcauVa6yZKwzsJGr5J/LANz+ZyHZmANed+2Hjqxu/H1NGDBdvUGLQb\n"
                                      "hb/uBJ8oG8iAW5eUyjEJMX0RuncYnBrUjZdEFr0zJd5VkrfFTd26AjGusbiBevAT\n"
                                      "fj83SNa9uK3N3lSNcLNyNXUjmfOU21NWHAk5QV3TJb6SCTcqWFaYoyKR7H6zxRcA\n"
                                      "rNuIAMW4KhOl4jdNnTxJllC4tr/gkE+uO1ntB9ymLxQBRp8osHjuZpKXr3cCAwEA\n"
                                      "AQKCAgAXtQGoRgzMDPnUb6WEPB2WMXJR3Id+1R21X/43lewqzcJ6Ieh2coSTvm15\n"
                                      "bramg6+Seh0zImdD2v+/Rzv5/x0I9cwJNvKfqGdN1wR8U8dzEcT/B3Wki9Kczxrc\n"
                                      "sj+3qvV4BePRwwwyHGuVYhC0QU/LoIVplMwzswIPG697oAbvxBEwW4cFh5qkDoqN\n"
                                      "y34ba5/jSyP610EfCpZSblht8F3XOlzh2644NmQHlOzuBj8MCj2o0iSvHSrgWOUN\n"
                                      "A8gi/zkTmGvktxoIGqxKdf0/wHcmXhK1B7268ldRPuCNhVxQ2eTInXXARPMsxiXC\n"
                                      "/yCKPzt+MMy8cZnJaFcthTdb/zxs5CKKgBKIl5svSW3ZO27SXJ8jo8m0cUUxwAQO\n"
                                      "jJCNroBMBlCDN/sILhpzgnPLkVXnK+/uUYSBe/oOHd7mL38ohlMPepbCeFu4r6fP\n"
                                      "xpOrROTIzDblg9/cne/TLqSPu2K6qbsXFoL3v95V9ieAETnGkTHuKwqW1gMYtOin\n"
                                      "Ad0GWIl4PZCAjbKptSFTM5/8nWiPdJ3YnkE0nQDSgK66ZRjyRCVSzE5CcgbiVlMW\n"
                                      "mXVsIXnt/RHsLsPuGuzURhSmjVg+x0g2nAPmnZuG+7wJOF1vVCYT1gufblaHEBAo\n"
                                      "ofcmYfdYxhd2iQmWJi/uwnC0f6YdF+wq+fLFuPMPgCMvdhe/oQKCAQEA6p8BV4qA\n"
                                      "aRbcV137k4/+jx3zrOA736kRjmHatR1fq0MDTk4JfvWrH5kfl8VS6b4fiYsDVTx6\n"
                                      "ylxYV1paqRUfNmfzuPQStM+arkFIw/6754CoESvqF/uU/JRe6WZIB1Jr3A4XNzZe\n"
                                      "p/9+0hJeQlwRUWPhWMUNIJPjaQ3kmdeIUEsRcIkf4e4xJzhilnxarK4/nkqicgo6\n"
                                      "H2JRD1QKtO96ncGDDLmwWXMxYA9RUHaURYten9bi36V8gt69/zI6B8uTyMJttUma\n"
                                      "ziMr4nBsvfJDT0C0LG9SqsAfPkUMWyHSXxXn7N7S4Yy48k+wyp6FMKN13d/aWqdy\n"
                                      "K4n2W8ux8sHMIQKCAQEAsBXh0HO8eZpanq3Vl0tiHmCpjTsXFUg/hOGrck4s/vaG\n"
                                      "mLiSqCHKX6qfoLrEWUiPfCuqBprAsSebq2c/xkWdwW1UP/6m6dh6REXHbZbTyot4\n"
                                      "JNSPwNSvfu3P6cmLFyao4u6AciO/V18kGXf64XsDZ9gb47oVGtcSmYcsHsVTIyE6\n"
                                      "84+UyO9ogT2CNBN7kHqP5LT5iQsX+YzQcJuEmCp8JO6Az/pkErH15p2uLIHHTXRK\n"
                                      "gGrazVRl4Gt4Qdx4dGk/WcTK6NDPeoi4Wki1DzzK0fJNUDYHItycZDK1bfY+2n+Q\n"
                                      "C5d40kIR4oRdHC0VF94clXuTD/Z7tpgN2vXODP9IlwKCAQAJVxUlmATuqhNRgxNN\n"
                                      "15Cpv+aAfljD2aYyReEADtBNMBjEmES2gi8yzdS9JQTc+02kGx2h2guFXNHDgHxV\n"
                                      "eNrKPq8sMMNB4XXl9AFilBSE7dFDBb2HAOP4fiudHQ5HBFf45bK05vwzse8pi8Om\n"
                                      "3qVt2Q0SjJ2uK1UFTKFKIpNxpttl4H+dbe8VAaCjHwY5E6LCuXPoGFIiB7b0ZkMa\n"
                                      "2uHFv/tomUfU98oCafmxu1bBwf+dW1+iyaLATv+/Vg+LWeZjOqJFck2wYSQRGqqp\n"
                                      "kShu0kOZ9UCUPZvAzdzlD96hHG0kN+arRf/i3ZtLJa5ltkwt7ghyTXI1G4PsOZq2\n"
                                      "8FIhAoIBAEYUf2n6FgIDt5s9ritnuiZC7FgkM1yqA3W8ZwK4MFpM/Wac1umJgUSv\n"
                                      "4JYUnv61zT1rF2FHh/c5v0/paM1deZq5C3XowL+DA65WYzevdp0/AtMNsiTZwPrw\n"
                                      "ZPYz22KcZUzkBUToC0gXuoNUaAoDbmiO7xKkRbAH9wQZcyrP9/WcTR0QgPOzrND7\n"
                                      "DO3y7xOiY9BvYnzzaFhOfcrDanMxPXVpYuTjT57NKwPcr6xQ/mRKKziOzoQ32dAG\n"
                                      "lbcIqvwRwz/T/bnJGTo4Xb64/y6QUFxcZf7NceujB68tK14XSg6mBEtIvrJXz0xq\n"
                                      "x6/mFWYJZTDtHKuWusgCHkmN2LL9iwMCggEAW00XBAIhaMskQh4TiBk8e2n8mBw3\n"
                                      "oqdRPgJ4LWLEdBxYJKoQCffyGW47qZXEvb416r5mq1XwHJlrYUqcf63Lj3ANAt+8\n"
                                      "ifE/FUhwb8jAiji6XTicDJERkM5HrxDA3TS2pbBM2/bIurOzBXGpXNpnMLKbNCur\n"
                                      "bvS5UcsSO5OvRH7JT4E5AwuuNPoiZb3nY/1wlC9VfzAc4tw5W1gMoElkiG1QxsMV\n"
                                      "ip5M37v06Exj2YURmRzIfhOGNgTf9NA91FZb73t94sUqxT0JbiWSA3llXKJn+NYr\n"
                                      "J04EngxPgHewJPwWf50GzLPK62OMKd7O5deTw+HO7qrClcpExZGsakc/cw==\n"
                                      "-----END RSA PRIVATE KEY-----";

static const char RSA_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                                     "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoWFe7BbX1nWo5oaSv/Jv\n"
                                     "IUCWsk/Vi2q8P0cGkefgN5J7MN7Kfv7lq0hl/1cZcJs81IC+GiC+V3aR2zLBNnJJ\n"
                                     "axa4sqk+hF5DJcD2bF0B80uqPYQUXlQwki/heATnVcke8APuY0kOZykxoD0APAqw\n"
                                     "0z5KDqgt2vA9G6keM6b9bbL+IvxM+yMk1QV0OQLh6Rkz46DyPSoUFWyXiist47PJ\n"
                                     "KNyZAfFZx6vEivzBmqRHKe11W9oD/tN5VTQCH/UTSRfyWq/UUMFVMCksLwT6XoWI\n"
                                     "7F5swgQkSahWkVJ93Qf8cUf1HIZYTMJBYPG4y2NDZ0+ytnH3BNXLMQXg9xbgv6B/\n"
                                     "iaSVScI4CWIpQTAtNKnJwYg2+RhfYBC07iM56c4a+TjbCWgmd11UYc96dbw83uFR\n"
                                     "jKZc3+SC38ITCgMuoDPNBlFJK6u8VfYylGEJolGcauVa6yZKwzsJGr5J/LANz+Zy\n"
                                     "HZmANed+2Hjqxu/H1NGDBdvUGLQbhb/uBJ8oG8iAW5eUyjEJMX0RuncYnBrUjZdE\n"
                                     "Fr0zJd5VkrfFTd26AjGusbiBevATfj83SNa9uK3N3lSNcLNyNXUjmfOU21NWHAk5\n"
                                     "QV3TJb6SCTcqWFaYoyKR7H6zxRcArNuIAMW4KhOl4jdNnTxJllC4tr/gkE+uO1nt\n"
                                     "B9ymLxQBRp8osHjuZpKXr3cCAwEAAQ==\n"
                                     "-----END PUBLIC KEY-----";

static const char ES256_PRIVATE_KEY_2[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                          "MHcCAQEEIFHGK6UXpOLxgdACDNSS8G3AqdkdHDMD2qObdmEAhdoloAoGCCqGSM49\n"
                                          "AwEHoUQDQgAESqXIVJc5sFwq4GvFleGoJYknNi0hj5TqFfjnLQRK7Cf6CmA7yQCT\n"
                                          "4W5yQBB5ovNcAqvUQP6RYgW83oKAL/2OHw==\n"
                                          "-----END EC PRIVATE KEY-----";

static const char ES256_PUBLIC_KEY_2[] = "-----BEGIN PUBLIC KEY-----\n"
                                         "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESqXIVJc5sFwq4GvFleGoJYknNi0h\n"
                                         "j5TqFfjnLQRK7Cf6CmA7yQCT4W5yQBB5ovNcAqvUQP6RYgW83oKAL/2OHw==\n"
                                         "-----END PUBLIC KEY-----";

static const char ES384_PRIVATE_KEY_2[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                          "MIGkAgEBBDCbjS+/FTuuhjJ7Lklyo9h1nlMH/0VcyCZlge58liaZ9g9Um/DSTT0V\n"
                                          "utL4VoxWFjGgBwYFK4EEACKhZANiAAQiH6BZV7ZHw5m9LY7ZOzK7uD97Vyi9u0B2\n"
                                          "BBe5w6jBQpzjahP4S91onTWzsYWymELbVYldfWDDU/Wvcnf1C8LkUz+tQlgPWoa+\n"
                                          "ENtOkE00vxH3PCOyBqQ2ZL+aI0XKi1s=\n"
                                          "-----END EC PRIVATE KEY-----";

static const char ES384_PUBLIC_KEY_2[] = "-----BEGIN PUBLIC KEY-----\n"
                                         "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESqXIVJc5sFwq4GvFleGoJYknNi0h\n"
                                         "j5TqFfjnLQRK7Cf6CmA7yQCT4W5yQBB5ovNcAqvUQP6RYgW83oKAL/2OHw==\n"
                                         "-----END PUBLIC KEY-----";

static const char ES512_PRIVATE_KEY_2[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                          "MIHcAgEBBEIA0Szh1UBd2jf92Es2Ow6Mp+qknIcuJbpu4PpcbDq7DnkfQmJY5bEK\n"
                                          "CVhWHWr2rBoPj3tZ1ZiXU/1OHzteQMzIt1egBwYFK4EEACOhgYkDgYYABABhAawu\n"
                                          "iJImltrUxMGACfuJvonUyHkVGxYHBjaiI4WxqjgqcNdpRUgdnFxPBrpcUTNJWTgG\n"
                                          "3AUsewUyBXd3keaoYACk4++ws2/voFOjrHlIM0rjaB1FLPvHUpPnaf9YAFI8bFrm\n"
                                          "6YtBo4uKejSGKNVmXwSE8iQOjgCa1zU14jZRMHZ06w==\n"
                                          "-----END EC PRIVATE KEY-----";

static const char ES512_PUBLIC_KEY_2[] = "-----BEGIN PUBLIC KEY-----\n"
                                         "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAYQGsLoiSJpba1MTBgAn7ib6J1Mh5\n"
                                         "FRsWBwY2oiOFsao4KnDXaUVIHZxcTwa6XFEzSVk4BtwFLHsFMgV3d5HmqGAApOPv\n"
                                         "sLNv76BTo6x5SDNK42gdRSz7x1KT52n/WABSPGxa5umLQaOLino0hijVZl8EhPIk\n"
                                         "Do4Amtc1NeI2UTB2dOs=\n"
                                         "-----END PUBLIC KEY-----";

static const char RSA_PRIVATE_KEY_2[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                                        "MIIJJwIBAAKCAgEAqQ1kJGUdpHNBmZWwnYM8PVhCeHx8sn9HCjb8RPkd3dhwuKPB\n"
                                        "p+9n7XmIcN9Vh8ZPaK1suphDF2BjTG78ddOrWIqeroenKvONKOUqPL5woDMFhCwV\n"
                                        "nGRgPLpaWNhf90Ngll+VJATeB8mwqqhhlMAnHAijwy2jFY48nvj6MGN7G+DTxSGK\n"
                                        "Q843Dugeh912OyhteflPPQhBW2bAvFiaG3DxyJpGFiPxhEsVmECB5wdm93FgeenN\n"
                                        "Z7MBb1uw4nDCT5Ca1vR5hDhVH68JQ4qokz3/ykdKl4Wy15ghf5X34/uL3t5kiyX2\n"
                                        "0U17ao0Oxu594VsKDvvJ6FFrg1hu/s8F+Wcy5A7ABcQ4zXdoaTZ16LDjn7DbszJO\n"
                                        "wy36dFbv4sM2BaCx5UrBnNsdCXxZBKzF/+wuNjrZetc/3eeWpyaImOJ/YtjhO5lk\n"
                                        "RZa7jFCgYfUi2zgTKJDsMhtc0dDU8dyb9hyi4cfp8+6z49zqg/pdyUhSdk6xcVEE\n"
                                        "0qi+T61QWBqr78lk4lZbV0wl7NmIsrmJ9iS3kfXPABZbbOfp1qWWXBea/l1XBbPV\n"
                                        "Pdp+AD3oS+ixsPsYfTQlQgF+p16FYXtZoiyn34wA+ONW8mMkoI+BIx4zE/qdYDgu\n"
                                        "jI0WIyLxpxt0ICMq7/SeDCPsBbk3JpPRL61787vQMiAQ+TRo379kY9FkbvsCAwEA\n"
                                        "AQKCAgAOgc+uL98zVZCzlVzqp3Br8z8BB+3Lg5CdF8reQGKHvyMtNSBRQQIyJtPG\n"
                                        "m+PDGwmFehxyhs57GxJqZLvVgKyblIm5gHqf/PaII+JUBCO2G6rFhOL14MdBbtyB\n"
                                        "80+I8IdBYEJ0LNbA5FX8zyZQlYzFoxgqj6gHGYWqPsN5k4/k/I4vxIkQ+IlRBipY\n"
                                        "jnCu8vEyHmrmWecB6PdxMklHQZH+HP8Wt07qg2b/AcokAUacxWX6EE5IL9xXqg6r\n"
                                        "3/FM0qP2/lPPPOZRKbwpx6RfvlpNCYElL5wBVFTLlhsHvXZrUbpfForvuy50Hla+\n"
                                        "S4kR5bYfQww4m4QWaWhdBXcFyA1d0PWFyBVij5y8h80hOg7nL0NYvBfyv9OubyxU\n"
                                        "tYsyFz0MWv7gQIB0I0arUzxlWrONf3HwGmUD0r5cEfWS97zxHS/wX21chuqtiHME\n"
                                        "242lGO1fHA580Yz2sWKThSse6iNK64lpoBH6xl/Xm+AgfZpxzBMoeNJXQ8reV3+F\n"
                                        "MAZJGVYVcWY4LUbTHT/gOVNq8iO8j83sT6yK/Er0KdIgFRGAkif4Jk4AcAINGe0A\n"
                                        "XpTNHGOJUjzv8PyZwxLw/RQzMCD7I9jVgEldabnSYlE25/l5Mr33QvM3Ldk/brX2\n"
                                        "LqnepgVdztTp1b1/lyPD2gj8VPzM9auA51ms7Fz72vJorC97AQKCAQEA4Q4xTDgS\n"
                                        "n2rHHTDciDjEfvUl/P+csrpbOrAa36alwSSfMzzkh7KfWQrVDCp8PRnKLDJcLMr0\n"
                                        "XPdrV8FWKI/hf3Nvua/SNX/wyf1jLwYheXGYRGvb1fFlatTC+/eOAsCuFUv3ybG0\n"
                                        "bgEII5bbD69B2UnTn6j/q1JFwXSQrCTIAWFl0pBiPOglQMkJq4Cy1YCZWuUKvU/i\n"
                                        "Uv/PIqUcO6NUYdhVbI8J30KviFimOWf4uIX++sJ5uqZ5MTzmMZh3o65Ib/n4W0OV\n"
                                        "n1gB3UMmjM4wwT79el5d6NslCR5YAkL+0vmA7q7RtiUFA+FW6tLifs7UaUbw3+jh\n"
                                        "14eTcNif2ls8SwKCAQEAwEvsnKNi2u+bVl84Qib53gewjn7oOK6ECqTWu98kCo+o\n"
                                        "xod8RNFCRoAjhgl2QFX171x9Jgk0NDfeNKqh5IuwOm2LFVau6AGBKh3WavW7RCnB\n"
                                        "ZQJMzSr1B/3GYIWhwx1UKSJNSIgQds3mXePdNZc3EzjMH5G3CPpTX2R8zQy/pox2\n"
                                        "tj5SfOWi/vCSbC+rNFPMYaDwuSSMABGzifBvPGVhtqUvFRrtD+ALVskUOW5Uyrx5\n"
                                        "l2qxyzCLaj8xXS7DpY2m6ZfftOsLyDQ3c87dMlUs9JTq5Ko2mr42LrNnpnss+J0M\n"
                                        "grceRKiJDgkz5wsfBu6U1OHPI//W/zSt5zSRaV+KEQKCAQBxjYKsLWKgEvUyMlQj\n"
                                        "W1kxoamwNJywxTyAqRh2HhRmFn9JEAFSwnqKJ+AFCm6zOY77q9E8PI79VU1Q8tjx\n"
                                        "EF+7udf2fdL3cX1hvTrNIC/Fod4tL6q1EN6V/5H+JhL+Ko/raPA2UTZzhou/wT74\n"
                                        "c/oqk4h2d4PAwns1uAXDBa/wml8Q1g7rIkqhnI4HfaE9/mviI8y+Zk8Qh8fQeDR9\n"
                                        "ltRdphS7+JQHlRMSHYCJWH9zQxC7H2LiHVrq0Appnb9H1AjyjtKT4c7dnj8aj+Yk\n"
                                        "h2isKIcmtfR2KBRQvIG1am4+rusyAv0HBTi5k3oSc6MaTmt4TvX8U/mXkO2As5w8\n"
                                        "RWpvAoIBABulTrkeTEIJnJ2IRwBLtjSTinCSEjTD8jvNgwmzhOz3xl30cIs8Qnj8\n"
                                        "Rx8oERYixZ7J/zwOqrCvL4UG2wuOgaGEyjAhLDgyry0s6Pyro2ajUiiBciU0/dFO\n"
                                        "TMznqV/xwX3Abrf0x9kstOfesJjZypM64S3Qty3VP1NBkSexo4QAQbjlsNo/8XUR\n"
                                        "hRuEpup4+bM3fiQ/+tivss4sAPH/6VJm4SP5oQddQIQTmJLBJ/OVsS1xq2n46rI1\n"
                                        "r5Uj+gC9IrgGm6TY/fKkfyxpGyf3UuU+255QUlVg7007gbVPlCGSApBwXyujx0B7\n"
                                        "VjjrQmSuvDr2097rEy/RlQbeaeFqWOECggEAM47eAjch+qICNLdowysWht0HjNPr\n"
                                        "FhTpVfXh4ybjdJU51EMh37oJtQ46QuBh0LnnbOS+p7DX59W6xN2KwawxMNkilK8M\n"
                                        "QWBp8kS5X0mc7TZkK4gqbXT3uSXS7boOi/tm1vFbHcm57XqjZK6oUGkT1bGlVceV\n"
                                        "9pPUr8vipUrCLVlq3INXM4b+VecMTHXMLLz1XHdCuw5t2wAV08sY22GogFNE8vfZ\n"
                                        "7+amO2WFoybdtZZjW4SmXAL+T+V8FQddzvmKj38bRHulqutf6LqRk2JfQCrwZp3x\n"
                                        "uDY3rROMPonHlZLZLX8nC430FzTYqnvkNwDS15oHYLl1JrLpZJ0/luPcrA==\n"
                                        "-----END RSA PRIVATE KEY-----";

static const char RSA_PUBLIC_KEY_2[] = "-----BEGIN PUBLIC KEY-----\n"
                                       "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqQ1kJGUdpHNBmZWwnYM8\n"
                                       "PVhCeHx8sn9HCjb8RPkd3dhwuKPBp+9n7XmIcN9Vh8ZPaK1suphDF2BjTG78ddOr\n"
                                       "WIqeroenKvONKOUqPL5woDMFhCwVnGRgPLpaWNhf90Ngll+VJATeB8mwqqhhlMAn\n"
                                       "HAijwy2jFY48nvj6MGN7G+DTxSGKQ843Dugeh912OyhteflPPQhBW2bAvFiaG3Dx\n"
                                       "yJpGFiPxhEsVmECB5wdm93FgeenNZ7MBb1uw4nDCT5Ca1vR5hDhVH68JQ4qokz3/\n"
                                       "ykdKl4Wy15ghf5X34/uL3t5kiyX20U17ao0Oxu594VsKDvvJ6FFrg1hu/s8F+Wcy\n"
                                       "5A7ABcQ4zXdoaTZ16LDjn7DbszJOwy36dFbv4sM2BaCx5UrBnNsdCXxZBKzF/+wu\n"
                                       "NjrZetc/3eeWpyaImOJ/YtjhO5lkRZa7jFCgYfUi2zgTKJDsMhtc0dDU8dyb9hyi\n"
                                       "4cfp8+6z49zqg/pdyUhSdk6xcVEE0qi+T61QWBqr78lk4lZbV0wl7NmIsrmJ9iS3\n"
                                       "kfXPABZbbOfp1qWWXBea/l1XBbPVPdp+AD3oS+ixsPsYfTQlQgF+p16FYXtZoiyn\n"
                                       "34wA+ONW8mMkoI+BIx4zE/qdYDgujI0WIyLxpxt0ICMq7/SeDCPsBbk3JpPRL617\n"
                                       "87vQMiAQ+TRo379kY9FkbvsCAwEAAQ==\n"
                                       "-----END PUBLIC KEY-----";
