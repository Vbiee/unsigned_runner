@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /std:c++17 /EHsc unsigned_runner.cpp /Fe:unsigned_runner.exe /link Wintrust.lib
