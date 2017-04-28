#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows XP
#define _WIN32_WINNT 0x0500     // Change this to the appropriate value to target other versions of Windows.
#endif

#include <windows.h>
#include <tchar.h>
#include <process.h>
#include "deadlock_detector.hpp"

int fire_collision = 0;
HANDLE hev = 0;

void f2(const char* prefix) 
{
   printf("%s::f2\n", prefix);    
}

void f1(const char* prefix) 
{
   printf("%s::f1\n", prefix); f2(prefix);
}

void f0(const char* prefix) 
{
   printf("%s::f0\n", prefix); f1(prefix);
   if (fire_collision)
      WaitForSingleObject(hev, INFINITE);
}

unsigned __stdcall thread0(void *ArgList) 
{
   for(;;)
   {
      f0("thread0");
   }
   return 0;
}

unsigned __stdcall thread1(void *ArgList) 
{
   for(;;)
   {
      f0("thread1");
   }
   return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
   hev = CreateEvent(0, 1, 0, 0);
   
   unsigned int thread_id;
   UTOOLS::_beginthreadex_dd(NULL, 0, thread0, NULL, 0, &thread_id, "Thread0");
   UTOOLS::_beginthreadex_dd(NULL, 0, thread1, NULL, 0, &thread_id, "Thread1");

   UTOOLS::DEADLOCK_DETECTOR* dd = UTOOLS::DEADLOCK_DETECTOR::instance();
   dd->run();

   Sleep(3000);
   fire_collision = 1;

   dd->wait_me();

	return 0;
}

