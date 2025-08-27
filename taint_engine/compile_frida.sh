SCRIPT=$1
SCRIPT_NAME=${SCRIPT%.*}

frida-compile -w $SCRIPT_NAME.js -o $SCRIPT_NAME\_compiled.js