
set PIN_ROOT=C:\libs\pin
set XED_ARCH=intel64
set BIONIC_ARCH=x86_64

cl /DPIN_CRT=1 /DTARGET_WINDOWS /DTARGET_IA32E /D__LP64__ /DHOST_IA32E ^
/MD /GR- /GS- /EHs- /EHa- /Oi- ^
 /I"%PIN_ROOT%\source\include\pin" ^
 /I"%PIN_ROOT%\extras\stlport\include" ^
 /I"%PIN_ROOT%\extras" ^
 /I"%PIN_ROOT%\extras\libstdc++\include" ^
 /I"%PIN_ROOT%\extras\crt\include" ^
 /I"%PIN_ROOT%\extras\crt" ^
 /I"%PIN_ROOT%\extras\crt\include\arch-%BIONIC_ARCH%" ^
 /I"%PIN_ROOT%\extras\crt\include\kernel\uapi" ^
 /I"%PIN_ROOT%\extras\crt\include\kernel\uapi\asm-x86" ^
 /I"%PIN_ROOT%\source\include\pin\gen" ^
 /I"%PIN_ROOT%\extras\components\include" ^
 /I"%PIN_ROOT%\extras\xed-intel64\include\xed" ^
 /D_WINDOWS_H_PATH_="C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" ^
 /FIinclude\msvc_compat.h main.cpp /link /NODEFAULTLIB ^
 /LIBPATH:"%PIN_ROOT%\%XED_ARCH%\runtime\pincrt" ^
 /LIBPATH:"%PIN_ROOT%\%XED_ARCH%\lib-ext" ^
 /LIBPATH:"%PIN_ROOT%\%XED_ARCH%\lib" ^
 /LIBPATH:"%PIN_ROOT%\extras\xed-%XED_ARCH%\lib" ^
 /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" ^
  /IGNORE:4210 /IGNORE:4049 ^
  /DLL ^
 "%PIN_ROOT%\%XED_ARCH%\runtime\pincrt\crtbeginS.obj" ^
  pin.lib xed.lib pincrt.lib pinipc.lib kernel32.lib /OUT:..\pintool.dll

