SET repo=%~dp0
SET out="%repo%\tests\build"
if exist %out% ( rd /s /q %out% ) 
mkdir %out% && cd %out%
cmake -DBUILD_SHARED_LIBS=Off -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
call Debug\run_tests.exe
cd ..\..

