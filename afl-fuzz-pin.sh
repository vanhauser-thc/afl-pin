#!/bin/sh
test -z "$1" -o "$1" = "-h" && {
  echo HELP for afl-fuzz-pin.sh :
  echo ================================
  echo you must it run like this:
  echo "  afl-fuzz-pin.sh -i in_dir -o out_dir -otheropt -- program -with -options"
  echo "Note the \"--\" - it is essential!"
  echo Note that you either have to instrument the program with :
  echo "  \"afl-dyninst -i program -o program_inst -D\""
  echo or use the option -forkserver which will will implement a fork server
  echo "in main(). You can specify a different entrypoint with -entrypoint otherfunc or 0x123456."
  echo To set memory requirements, set AFL_MEM=700 for 700mb, default is none.
  echo Options:
  echo " -forkserver   install a forkserver - you usually want this!"
  echo " -entrypoint 0xaddr  where to install the forkserver if main() can not be found"
  echo " -exitpoint 0xaddr   where to terminate the program (for speed)"
  echo " -alternative  alternate mode, faster, but with lower quality"
  exit 1
}

test -z "$PIN_ROOT" -a -n "$PIN_HOME" && PIN_ROOT=$PIN_HOME
test -z "$PIN_ROOT" && { echo Error: environment variable PIN_ROOT is not set ; exit 1 ; }
test -x "$PIN_ROOT/pin" || { echo "Error: environment variable PIN_ROOT is not pointing to the build directory (where the pin binary is residing)" ; exit 1 ; }
CLIENT=
test -e ./afl-pin.so && CLIENT=./afl-pin.so 
test -z "$CLIENT" -a -e "/usr/local/lib/pintool/afl-pin.so" && CLIENT=/usr/local/lib/pintool/afl-pin.so
test -z "$CLIENT" && { echo Error: can not find afl-pin.so either in the current directory nor in /usr/local/lib/pintool ; exit 1 ; }

test -z "$AFL_MEM" && AFL_MEM=none

AFLPIN=""

OPS=
LOAD=
while [ '!' "$1" = "--" ]; do
  OK=
  test -z "$1" && { echo Error: no -- switch found ; exit 1 ; }
  test "$1" = "-alternative" && { shift ; AFLPIN="$AFLPIN -alternative" ; OK=1 ; }
  test "$1" = "-libs" && { shift ; AFLPIN="$AFLPIN -libs" ; OK=1 ; }
  test "$1" = "-forkserver" && { shift ; AFLPIN="$AFLPIN -forkserver" ; OK=1 ; LOAD=1 ; }
  test "$1" = "-entrypoint" && { shift ; AFLPIN="$AFLPIN -entrypoint $1" ; shift ; OK=1 ; }
  test "$1" = "-exitpoint" && { shift ; AFLPIN="$AFLPIN -exitpoint $1" ; shift ; OK=1 ; }
  test -z "$OK" && { OPS="$OPS $1" ; shift ; }
done

sysctl -w kernel.core_pattern=core
sysctl -w kernel.randomize_va_space=0
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null

export AFL_SKIP_BIN_CHECK=1
export DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.
export AFL_EXIT_WHEN_DONE=1
#export AFL_TMPDIR=/run/$$
#export AFL_PRELOAD=./desock.so:./libdislocator/libdislocator.so

echo Running: afl-fuzz -m $AFL_MEM $OPS -- $PIN_ROOT/pin -t "$CLIENT" $AFLPIN $*
sleep 1
test -n "$LOAD" && export PIN_APP_LD_PRELOAD=/usr/local/lib/pintool/forkserver.so
afl-fuzz -m $AFL_MEM $OPS -- $PIN_ROOT/pin -t "$CLIENT" $AFLPIN $*
