SET i=%CD%
SET repo=%~dp0
SET out="%repo%\build"
SET projname=L8W8JWT

if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out%

cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off "-D%projname%_ENABLE_TESTS=On" "-D%projname%_ENABLE_EDDSA=On" "-D%projname%_SMALL_STACK=On" ..

cmake --build . --config Release || exit

call Release\run_tests.exe || exit

cd %i%