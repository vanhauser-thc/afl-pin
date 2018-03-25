#include "pin.H"
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <sstream>
#include <sys/types.h>
#include <sys/shm.h>
#include "afl/config.h"

#if PIN_PRODUCT_VERSION_MAJOR < 3
 #if PIN_PRODUCT_VERSION_MINOR < 6
  #warn "WARNING: you should use pintool >= 3.6!"
 #endif
#endif

KNOB < BOOL > KnobAlt(KNOB_MODE_WRITEONCE, "pintool", "alternative", "0", "use alternative mode for bb reporting");
KNOB < BOOL > KnobLibs(KNOB_MODE_WRITEONCE, "pintool", "libs", "0", "also report basic bocks of dynamic libraries");
KNOB < BOOL > KnobForkserver(KNOB_MODE_WRITEONCE, "pintool", "forkserver", "0", "install a fork server into main");
KNOB < string > KnobEntrypoint(KNOB_MODE_WRITEONCE, "pintool", "entrypoint", "main", "install a fork server into this function (name or 0xaddr)");
KNOB < string > KnobExitpoint(KNOB_MODE_WRITEONCE, "pintool", "exitpoint", "", "exit the program when this function or address is reached");

typedef uint16_t map_t;

static int libs = 0, doit = 0, imageload = 0;
static ADDRINT exe_start = 0, exe_end = 0;
static map_t prev_id;
RTN entrypoint, exitpoint;
static ADDRINT forkserver = 0, exitfunc = 0;
#ifndef DEBUG
static uint8_t *trace_bits = NULL;
#endif

/* ===================================================================== */
/* Usage                                                                 */
/* ===================================================================== */

INT32 Usage() {
  cout << "afl-pin (c) 2018 by Marc \"van Hauser\" Heuse <mh@mh-sec.de> AGPL 3.0" << endl;
  cout << "=====================================================================" << endl;
  cout << " -libs         also report basic bocks of dynamic libraries" << endl;
  cout << " -alternative  report all basic blocks, not only conditional and indirect ones" << endl;
  cout << " -forkserver   insert forkserver into main() (otherwise use afl-dyninst -D)" << endl;
  cout << "   Note: load the forkserver.so via PIN_APP_LD_PRELOAD or use afl-fuzz-pin.sh" << endl;
  cout << " -entrypoint dst  specify a location for the forkserver, funcname or 0xaddr" << endl;
  cout << " -exitpoint dst   specify a location where the program will exit" << endl;
  return -1;
}

static VOID PIN_FAST_ANALYSIS_CALL bbreport(ADDRINT addr) {
  if (doit == 0)
    return;
  map_t id = (map_t)(((uintptr_t)addr) >> 1);
#ifdef DEBUG
  cerr << "BB: 0x" << hex << addr << " and id 0x" << (prev_id ^ id) << endl;;
#else
  trace_bits[prev_id ^ id]++;
#endif
  prev_id = id >> 1;
}

static VOID Trace_alt(TRACE trace, VOID *v) {
  BBL bbl = TRACE_BblHead(trace);
  if (exe_start != 0 && (BBL_Address(bbl) > exe_end || BBL_Address(bbl) < exe_start))
    return;
  for ( ; BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)bbreport, IARG_FAST_ANALYSIS_CALL,
                   IARG_ADDRINT, BBL_Address(bbl), IARG_END);
  }
}

static VOID Trace(TRACE trace, VOID *v) {
  BBL bbl = TRACE_BblHead(trace);
  if (exe_start != 0 && (BBL_Address(bbl) > exe_end || BBL_Address(bbl) < exe_start))
    return;
  for ( ; BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    INS ins = BBL_InsTail(bbl);
#ifdef DEBUG
    cerr << "DEBUG: INS@BB at 0x" << BBL_Address(bbl) << " " << INS_Disassemble(ins) << " => isfallthrough:" << INS_HasFallThrough(ins) << " condbranch:" << (INS_Category(ins) == XED_CATEGORY_COND_BR) << " indirect:" << INS_IsIndirectBranchOrCall(ins) << " isret:" << INS_IsRet(ins) << endl;
#endif
    if (INS_IsRet(ins) == false && (INS_Category(ins) == XED_CATEGORY_COND_BR || INS_IsIndirectBranchOrCall(ins) == true))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bbreport, IARG_BRANCH_TARGET_ADDR, IARG_END);
  }
}

static void DTearly() { PIN_Detach(); }

static VOID startForkServer(CONTEXT *ctxt, THREADID tid) {
  PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_DEFAULT, AFUNPTR(forkserver), NULL, PIN_PARG_END());
}

static VOID exitFunction(CONTEXT *ctxt, THREADID tid) {
  PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_DEFAULT, AFUNPTR(exitfunc), NULL, PIN_PARG_END());
}

VOID Image(IMG img, VOID * v) {
#ifdef DEBUG
  cerr << "DEBUG: image load no " << imageload << " for " << IMG_Name(img) << " from " << hex << IMG_LowAddress(img) << " to " << IMG_HighAddress(img) << endl ;
#endif
  
  if (imageload == 0) {
    if (libs == 0) {
      exe_start = IMG_LowAddress(img);
      exe_end = IMG_HighAddress(img);
    }
    if (KnobForkserver.Value()) {
      entrypoint = RTN_FindByName(img, KnobEntrypoint.Value().c_str());
      if (entrypoint == RTN_Invalid()) {
        entrypoint = RTN_FindByAddress(strtoul(KnobEntrypoint.Value().c_str(), NULL, 16));
        if (entrypoint == RTN_Invalid()) {
          entrypoint = RTN_FindByName(img, "__libc_start_main");
          if (entrypoint == RTN_Invalid()) {
            fprintf(stderr, "Error: could not find entrypoint %s\n", KnobEntrypoint.Value().c_str());
            exit(-1);
          }
        }
      }
    }
    if (KnobExitpoint.Value().length() > 0) {
      exitpoint = RTN_FindByName(img, KnobExitpoint.Value().c_str());
      if (exitpoint == RTN_Invalid()) {
        exitpoint = RTN_FindByAddress(strtoul(KnobExitpoint.Value().c_str(), NULL, 16));
        if (exitpoint == RTN_Invalid()) {
          fprintf(stderr, "Warning: could not find exitpoint %s\n", KnobExitpoint.Value().c_str());
        }
      }
    }
  }
  if (exitpoint != RTN_Invalid() && exitfunc == 0) {
    RTN rtn = RTN_FindByName(img, "_exit");
    if (rtn != RTN_Invalid()) {
      exitfunc = RTN_Address(rtn);
      if (exitfunc != 0) {
        RTN_Open(exitpoint);
        RTN_InsertCall(exitpoint, IPOINT_BEFORE, (AFUNPTR)exitFunction, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
        RTN_Close(exitpoint);
      }
    }
  }
  if (entrypoint != RTN_Invalid() && IMG_Name(img).find("forkserver.so") != string::npos) {
    RTN rtn = RTN_FindByName(img, "startForkServer");
    if (rtn == RTN_Invalid()) {
      fprintf(stderr, "Error: could not find startForkServer in forkserver.so\n");
      exit(-1);
    }
    forkserver = RTN_Address(rtn);
    RTN_Open(entrypoint);
    RTN_InsertCall(entrypoint, IPOINT_BEFORE, (AFUNPTR)startForkServer, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
    RTN_InsertCall(entrypoint, IPOINT_AFTER, (AFUNPTR)DTearly, IARG_END);
    RTN_Close(entrypoint);
  }
  ++imageload;
}

VOID fini(INT32 code, VOID * v) {
#ifdef DEBUG
  cerr << "DEBUG: END OF PROGRAM" << endl;
#endif
  return;
}

VOID AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID * arg) {
#ifdef DEBUG
  cerr << "DEBUG: After fork in child " << threadid << endl;
#endif
  doit = 1;
  prev_id = 0;
}

/* ===================================================================== */
/* MAIN function                                                         */
/* ===================================================================== */

int main(int argc, char *argv[]) {
#ifndef DEBUG
  char *shmenv;
  int shm_id;
#endif
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();
  PIN_SetSyntaxIntel();

  if (KnobLibs.Value())
    libs = 1;

#ifndef DEBUG
  if ((shmenv = getenv(SHM_ENV_VAR)) == NULL) {
    fprintf(stderr, "Error: AFL environment variable " SHM_ENV_VAR " not set\n");
    exit(-1);
  }
  if ((shm_id = atoi(shmenv)) < 0) {
    fprintf(stderr, "Error: invalid " SHM_ENV_VAR " contents\n");
    exit(-1);
  }
  if ((trace_bits = (u8 *) shmat(shm_id, NULL, 0)) == (void*) -1 || trace_bits == NULL) {
    fprintf(stderr, "Error: " SHM_ENV_VAR " attach failed\n");
    exit(-1);
  }
  if (fcntl(FORKSRV_FD, F_GETFL) == -1 || fcntl(FORKSRV_FD + 1, F_GETFL) == -1) {
    fprintf(stderr, "Error: AFL fork server file descriptors are not open\n");
    exit(-1);
  }
#endif

  entrypoint = RTN_Invalid();
  exitpoint = RTN_Invalid();
  if (libs == 0 || KnobForkserver.Value() || KnobExitpoint.Value().length() > 0)
    IMG_AddInstrumentFunction(Image, 0);
#ifdef DEBUG
  doit = 1;
#endif

  PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
  PIN_AddFiniFunction(fini, 0);
  if (KnobAlt.Value())
    TRACE_AddInstrumentFunction(Trace_alt, NULL);
  else
    TRACE_AddInstrumentFunction(Trace, NULL);
  PIN_StartProgram();

  return 0;
}
