cd "tests"
if exist "build" ( rd /s /q "build") 
mkdir "build" && cd "build"
cmake -DBUILD_SHARED_LIBS=Off -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
call Debug\run_tests.exe
cd ..\..

