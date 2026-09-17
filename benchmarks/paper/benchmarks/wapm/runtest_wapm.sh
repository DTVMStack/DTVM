#!/bin/bash
set -e

VM="$1"
work_path="case/wapm"

function Initialization_parameters()
{
    DIR=''
    COMMAND=':'
    PARAMETER=''
    HEAD_COMMAND=''
    UNEXPECTED_CASE=''
}

function Initialization_parameters_vm_parameters()
{
    if [ $# -eq 0 ] || [ $VM = iwasm ]
    then
        set -e
        skip_num=0
        FAILED_CASENAME=''
        source case/wapm/iwasm.conf
    elif [ $VM = wasmtime ]
    then
        source case/wapm/wasmtime.conf
        skip_num=$(echo $FAILED_CASENAME | awk -F'wasm' '{print NF-1}')
        RUN_COMMAND="$work_path/$case_name"
    else
        echo "Parameter error,Please use the correct parameter iwasm or wasmtime,Without any parameters, iwasm is used by default"
        echo -e '\n'Usage: ./case/wapm/runtest_wapm.sh [parameter]'\n'
        exit 1
    fi
}

function return_code()
{
    if [ $? -eq 0 ]
    then
        let pass_num+=1
        echo -e "\n\033[32m testing $case_name Pass \033[0m"
        echo -e '\n'
    else
        let pass_num-=1
        echo -e "\033[31m testing $case_name Failed \033[0m"
        echo -e "\033[31m The total number of use cases is $NUM, the test passed $pass_num use cases, the current test case is abnormal, and the abnormal use case name is $case_name \033[0m"
        echo -e '\n\n'
        exit 1
    fi
}

pass_num=0;fail_num=0
NUM=`ls $work_path | grep wasm$ | wc -l`
echo wapm-testsuite Start testing
echo -e '\n'
while read line
do
    Initialization_parameters
    case_name=`echo $line | awk '{print $1}'`
    RUN_COMMAND="--heap-size=0 --stack-size=8000000 $work_path/$case_name"
    Initialization_parameters_vm_parameters
    echo '### Testing' $case_name '###'
    if [[ $FAILED_CASENAME =~ $case_name  ]]
    then
        let pass_num-=1
    elif [[ $RANDOMCASE =~ $case_name ]]
    then
        source $work_path/$case_name.conf
        $VM $DIR $work_path/$case_name $PARAMETER
        return_code
    else
        expected_name=`ls $work_path/$case_name`.expected
        conf_name=`echo $line | awk '{print $1}'`.conf
        src_str=`cat $expected_name`
        source $work_path/$conf_name

        if [ "$case_name" = "$UNEXPECTED_CASE" ]
        then
            $HEAD_COMMAND "$COMMAND | $VM $DIR $RUN_COMMAND $PARAMETER|$PARAMETER2" |tee $expected_name
        else
            $HEAD_COMMAND $COMMAND | $VM $DIR $RUN_COMMAND $PARAMETER | tr -d '\000' | tee $work_path/$case_name.expected
        fi
        dest_str=`cat $expected_name`

        if [[ "$dest_str" = "$src_str" ]]
        then
            let pass_num+=1
            echo -e "\n\033[32m testing $case_name Pass \033[0m"
            echo -e '\n'
        else
            let pass_num-=1
            echo -e "\033[31m Test case exception \033[0m"
            echo -e "\033[31m The total number of use cases is $NUM, the test passed $EXPECTED_NAME use cases, the current test case is abnormal, and the abnormal use case name is $case_name \033[0m"
            echo -e '\n\n'
            exit 1
        fi
    fi
done <<< `ls $work_path | grep wasm$`
skip_num=`echo ${CASE_NAME[@]} | grep -o '\.wasm' | wc -l`
NUM=`expr $NUM - $skip_num`
echo "### wapm-testsuite End testing"
echo IN ALL $NUM  cases: $NUM PASS , 0 FAIL , 0 SKIP ;
echo -e "\033[32m wapm-testsuite TEST SUCCESSFUL \033[0m"
echo -e '\n\n'
