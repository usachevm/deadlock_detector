#include "deadlock_detector.hpp"
#include <Dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

DEADLOCK_DETECTOR* DEADLOCK_DETECTOR::singleton = NULL;

#define HASH_ROT13_CHAR(hash, ch)                     \
   hash += (unsigned char)(ch);                       \
   hash -= (hash << 13) | (hash >> 19);

#define HASH_ROT13_DWORD(hash, dw)                    \
   HASH_ROT13_CHAR(hash, (((DWORD)dw)&0xFF));         \
   HASH_ROT13_CHAR(hash, ((((DWORD)dw)>>8)&0xFF));    \
   HASH_ROT13_CHAR(hash, ((((DWORD)dw)>>16)&0xFF));   \
   HASH_ROT13_CHAR(hash, ((((DWORD)dw)>>24)&0xFF));      

DEADLOCK_DETECTOR::DEADLOCK_DETECTOR()
{
   InitializeCriticalSection(&cs);
   deadlock_detected = FALSE;
   ev_stop = CreateEvent(NULL, FALSE, FALSE, NULL);
   ev_monitor_finished = CreateEvent(NULL, FALSE, FALSE, NULL);
   hthread = INVALID_HANDLE_VALUE;
   SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
   SymInitialize(GetCurrentProcess(), NULL, TRUE);
}

DEADLOCK_DETECTOR::~DEADLOCK_DETECTOR()
{
   stop();
   CloseHandle(ev_stop);
   CloseHandle(ev_monitor_finished);
}

DWORD DEADLOCK_DETECTOR::__ebp(HANDLE hthread)
{
   CONTEXT ctx;
   ZeroMemory(&ctx, sizeof(ctx));
   ctx.ContextFlags = CONTEXT_CONTROL;
   BOOL valid = GetThreadContext(hthread, &ctx);
   if (!valid)
   {
      enum {BFSZ=4096};
      wchar_t bf[BFSZ];      
      swprintf_s(bf, BFSZ, L"GetThreadContext Error: 0x%08X\n", GetLastError());
      OutputDebugString(bf);
   }
   return valid ? ctx.Ebp : 0;
}

void DEADLOCK_DETECTOR::__add_thread(HANDLE hthread, const std::string& name)
{
   EnterCriticalSection(&cs);
   THREADCONTEXT ctx = {1, GetThreadId(hthread), 0, name, 0, 0, 0};
   ctx.callstack.reserve(256);
   tctx.push_back(ctx);
   LeaveCriticalSection(&cs);
}

void DEADLOCK_DETECTOR::__snapshot(BOOL update_callstack)
{
   EnterCriticalSection(&cs);
   INT cnt = tctx.size();
   // 1. Suspend all threads in the list
   INT cnt_valid = 0;
   for(INT i=0; i<cnt; i++) 
   {
      if (!tctx[i].valid)
         continue;
      tctx[i].hthread = OpenThread(THREAD_ALL_ACCESS, 0, tctx[i].thread_id);
      if (tctx[i].hthread)
      {
         SuspendThread(tctx[i].hthread);
         cnt_valid++;
      }
      else
      {
         tctx[i].valid = 0;
         enum {BFSZ = 4096};
         wchar_t bf[BFSZ];
         swprintf_s(bf, BFSZ, L"Thread %S (%d) has been removed from monitoring\n", tctx[i].name.c_str(), tctx[i].thread_id);
         OutputDebugString(bf);
      }
   }
   // 2. Capture thread callstack
   deadlock_detected = cnt_valid > 0;
   for(INT i=0; i<cnt; i++)
   {
      if (update_callstack)
         tctx[i].callstack.clear();
      if (tctx[i].hthread == NULL)
         continue;
      DWORD* ebp = (DWORD*)__ebp(tctx[i].hthread);
      INT depth = 0;
      DWORD hash = 0;
      while(ebp && *ebp)
      {
         HASH_ROT13_DWORD(hash, ebp[1]);     // hash eip
         if (update_callstack)
            tctx[i].callstack.push_back(ebp[1]);
         ebp = (DWORD*) ebp[0];
         depth++;
      }
      HASH_ROT13_DWORD(hash, depth);
      if (tctx[i].hash == hash)
      {
         // it is possible a thread has been deadlocked
         tctx[i].idle_cnt++;
         tctx[i].state_idle = TRUE;
      }
      else
      {
         // a thread is active
         tctx[i].hash = hash;
         tctx[i].state_idle = FALSE;
         deadlock_detected = FALSE;
      }
   }
   // 3. Resume all suspended threads
   for(INT i=0; i<cnt; i++) 
   {
      if (tctx[i].hthread)
      {
         ResumeThread(tctx[i].hthread);
         CloseHandle(tctx[i].hthread);
      }
   }
   LeaveCriticalSection(&cs);
}

BOOL DEADLOCK_DETECTOR::__is_deadlock()
{
   EnterCriticalSection(&cs);
   BOOL deadlock = deadlock_detected;
   LeaveCriticalSection(&cs);
   return deadlock;
}

void DEADLOCK_DETECTOR::run(const wchar_t* log_fname)
{
   logname = log_fname ? log_fname : L"";
   unsigned int thread_id;
   hthread = (HANDLE) _beginthreadex(NULL, 0, thread_monitor, NULL, 0, &thread_id);
}

unsigned __stdcall DEADLOCK_DETECTOR::thread_monitor(void *ArgList) 
{
   DEADLOCK_DETECTOR* fw = DEADLOCK_DETECTOR::instance();
   fw->running = TRUE;
   OutputDebugString(L"Monitoring has been started\n");
   enum {MAX_WATCHDOG = 50};           // 5 seconds
   INT watchdog = MAX_WATCHDOG;
   while(TRUE)
   {
      fw->__snapshot(FALSE);
      if (fw->__is_deadlock())
      {
         watchdog--;
         if (!watchdog)
         {
            OutputDebugString(L"\n*** Deadlock detected! ***\n\n");
            fw->dump();
            break;
         }
      }
      else
         watchdog = MAX_WATCHDOG;
      if (WaitForSingleObject(fw->ev_stop, 100) != WAIT_TIMEOUT)
         break;
   }
   OutputDebugString(L"Monitoring has been stopped\n");
   fw->running = FALSE;
   SetEvent(fw->ev_monitor_finished);
   return 0;
}

void DEADLOCK_DETECTOR::dump()
{
   EnterCriticalSection(&cs);

   __snapshot(TRUE);
   
   FILE* f = NULL;
   if (!logname.empty())
   {
      _wfopen_s(&f, logname.c_str(), L"w+b");
      WORD bom = 0xFEFF;
      fwrite(&bom, sizeof(bom), 1, f);
   }

   char buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
   PSYMBOL_INFO sym = (PSYMBOL_INFO) buf;
   sym->MaxNameLen = 256;
   sym->SizeOfStruct = sizeof(SYMBOL_INFO);
   IMAGEHLP_LINE64 line;
   line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

   HANDLE hprocess = GetCurrentProcess();   
   DWORD displacement32;

   struct PRINTER
   {
      static void print(FILE* f, const wchar_t* txt)
      {
         if (f)
            fwrite(txt, sizeof(wchar_t), wcslen(txt), f);
         else
            OutputDebugString(txt);
      }
   };

   enum {BFSZ = 4096};
   wchar_t bf[BFSZ];
   INT cnt = tctx.size();   
   for(INT i=0; i<cnt; i++)
   {
      if (tctx[i].valid)
      {
         swprintf_s(bf, BFSZ, L"[%d] thread %S (%d) is %s\n", i, tctx[i].name.c_str(), tctx[i].thread_id, tctx[i].state_idle ? L"idle" : L"active");
         PRINTER::print(f, bf);
         INT callcnt = tctx[i].callstack.size();
         for(INT j=0; j<callcnt; j++)
         {
            DWORD eip = tctx[i].callstack[j];
            if (SymFromAddr(hprocess, (DWORD64)eip, NULL, sym))
            {
               if (SymGetLineFromAddr64(hprocess, (DWORD64)eip, &displacement32, &line))
                  swprintf_s(bf, BFSZ, L"  [%d] %S +0x%X (0x%08X), source %S:%d\n", j, sym->Name, displacement32, eip, line.FileName, line.LineNumber);
               else
                  swprintf_s(bf, BFSZ, L"  [%d] %S (0x%08X), source unavailable\n", j, sym->Name, eip);
            }
            else
               swprintf_s(bf, BFSZ, L"  [%d] 0x%08X, source unavailable\n", j, eip);
            PRINTER::print(f, bf);
         }
      }
      else
      {
         swprintf_s(bf, BFSZ, L"[%d] thread %S (%d) was interrupted\n", i, tctx[i].name.c_str(), tctx[i].thread_id);
         PRINTER::print(f, bf);
      }
      PRINTER::print(f, L"\n");
   }
   
   if (f)
      fclose(f);
   
   LeaveCriticalSection(&cs);
}


uintptr_t __cdecl _beginthreadex_dd(_In_opt_ void * _Security, _In_ unsigned _StackSize, _In_ unsigned (__stdcall * _StartAddress) (void *), _In_opt_ void * _ArgList, _In_ unsigned _InitFlag, _In_opt_ unsigned * _ThrdAddr, const char* thread_name)
{
   uintptr_t hthread = _beginthreadex(_Security, _StackSize, _StartAddress, _ArgList, _InitFlag, _ThrdAddr);
   DEADLOCK_DETECTOR::instance()->__add_thread((HANDLE) hthread, thread_name);
   return hthread;
}
