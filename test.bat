SET repo=%~dp0
SET out="%repo%\build-msvc"
if exist %out% ( rd /s /q %out% ) 
mkdir %out% && cd %out%
cmake -DBUILD_SHARED_LIBS=Off -DL8W8JWT_ENABLE_TESTS=On -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
call Debug\run_tests.exe
cd ..

