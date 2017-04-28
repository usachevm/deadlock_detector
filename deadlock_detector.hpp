#pragma once

#include <windows.h>
#include <process.h>
#include <vector>
#include <string>

// use this instead of _beginthreadex(...) to provide deadlock detection functionality
uintptr_t __cdecl _beginthreadex_dd(_In_opt_ void * _Security, _In_ unsigned _StackSize,
     _In_ unsigned (__stdcall * _StartAddress) (void *), _In_opt_ void * _ArgList, 
     _In_ unsigned _InitFlag, _In_opt_ unsigned * _ThrdAddr, const char* thread_name);


class DEADLOCK_DETECTOR
{
   friend uintptr_t __cdecl _beginthreadex_dd(_In_opt_ void * _Security, _In_ unsigned _StackSize,
     _In_ unsigned (__stdcall * _StartAddress) (void *), _In_opt_ void * _ArgList, 
     _In_ unsigned _InitFlag, _In_opt_ unsigned * _ThrdAddr, const char* thread_name);
   public:
      static DEADLOCK_DETECTOR* instance() {return singleton ? singleton : (singleton = new DEADLOCK_DETECTOR());}
      ~DEADLOCK_DETECTOR();
      
      void run(const wchar_t* log_fname = NULL);
      void stop() {SetEvent(ev_stop);}
      void wait_me() {WaitForSingleObject(ev_monitor_finished, INFINITE);}
      
      void dump();
   private:
      DEADLOCK_DETECTOR();

      void __add_thread(HANDLE hthread, const std::string& name);
      BOOL __is_deadlock();

      void __snapshot(BOOL update_callstack);
      DWORD __ebp(HANDLE hthread);
      
      static unsigned __stdcall thread_monitor(void *ArgList);
   private:
      static DEADLOCK_DETECTOR* singleton;
      CRITICAL_SECTION cs;
      HANDLE ev_stop;
      HANDLE ev_monitor_finished;
      HANDLE hthread;
      BOOL deadlock_detected;
      BOOL running;
      std::wstring logname;
      
      struct THREADCONTEXT
      {
         BOOL valid;
         DWORD thread_id;
         HANDLE hthread;
         std::string name;
         DWORD hash;
         DWORD idle_cnt;
         BOOL state_idle;
         std::vector<DWORD> callstack;
      };      
      std::vector<THREADCONTEXT> tctx;
};

