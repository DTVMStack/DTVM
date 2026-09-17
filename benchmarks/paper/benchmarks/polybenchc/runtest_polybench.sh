#!/bin/bash
set -e

VM="$1"
work_path="case/PolyBenchC"
pass_num=0;skip_num=0

if [ $# -eq 0 ] || [ $1 = iwasm ]
then
    set -e
    source case/PolyBenchC/iwasm.conf
    echo 
elif [ $1 != wasmtime ]
then
    echo "Parameter error,Please use the correct parameter iwasm or wasmtime,Without any parameters, iwasm is used by default"
    echo -e '\n'Usage: ./case/PolyBenchC/runtest_polybench.sh [parameter]'\n'
    exit 1
fi


function test()
{
    NUM=`ls case/PolyBenchC | grep wasm| wc -l`
    echo PolyBenchC-testsuite Start testing
    while read line
    do
        case_name=`echo $line | awk '{print $1}'`
        echo '### Testing' $case_name '###'
        $VM case/PolyBenchC/$case_name
        
        if [ $? -eq 0 ]
        then
            let pass_num+=1
            echo -e "\033[32m testing $case_name Pass \033[0m"
            echo -e '\n'
        else
            let pass_num-=1
            echo -e "\033[31m testing $case Failed \033[0m"
            echo -e "\033[31m Test case exception \033[0m"
            echo -e "\033[31m The total number of use cases is $NUM, the test passed $pass_num use cases, the current test case is abnormal, and the abnormal use case name is $case_name \033[0m"
_num=`expr $NUM - $pass_num - 1`
            echo "### PolyBenchC-testsuite End testing"
            echo IN ALL $NUM  cases: $pass_num PASS , 1 FAIL , $skip_num SKIP ;
            echo -e '\n\n'
            exit 1
        fi
    done <<< `ls case/PolyBenchC | grep wasm$`

}

test

echo "### PolyBenchC-testsuite End testing"
echo IN ALL $NUM  cases: $NUM PASS , 0 FAIL , 0 SKIP ;
echo -e "\033[32m PolyBenchC-testsuite TEST SUCCESSFUL \033[0m"
echo -e '\n\n'
