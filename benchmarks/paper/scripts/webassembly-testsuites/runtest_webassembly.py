#!/usr/bin/env python3

import os
import sys
import time
import difflib
import argparse
import subprocess
import re

base_dir = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(base_dir)

startdir = os.getcwd()
os.chdir(base_dir)

parser = argparse.ArgumentParser()

parser.add_argument("-r", "--run", dest = "run", nargs = '+',
                     default = ["iwasm"],
                     help = "specify a runtime [path/to]([iwasm] / wasmtime / dtvm / wasmer run)")
parser.add_argument("-s", "--suite", dest = "suite_name", nargs = '+',
                     default = [ 'c', 'emcc', 'wasi', 'wapm', 'issues', 'wabench', 'java2wasm', 'malformed', 'libsodium', 'polybenchc', 'sightglass', 'smartcontract', 'standalone', 'perfcontract', 'assemblyscript' ],
                     help = "Specify a test suite [test suite name]([c] / emcc / wasi / wapm / spec / issues / wabench / java2wasm / malformed / libsodium / polybenchc / sightglass / smartcontract / standalone / perfcontract / assemblyscript )")
parser.add_argument("--dtvm-options", dest = "dtvm_options", nargs = '?', default = "", help = "options for dtvm cli")

args = parser.parse_args()

class commandline_parsing:
    def __init__(self):
        
        runstr = "".join(args.run)

        if runstr.startswith('/') == True:
            self.argsrun = runstr
        elif '..' in runstr:
            self.argsrun = startdir + "/" + runstr
        elif './' in runstr:
            argsrunstr = runstr.replace(".", "")
            self.argsrun = startdir + argsrunstr
        elif '/' not in runstr:
            self.argsrun = runstr

        if '/' in self.argsrun:
            self.runtime = self.argsrun.rsplit('/', 1)[1]
            self.command_detection()
        else:
            self.runtime = self.argsrun

    def command_detection(self):
        if os.path.isfile(self.argsrun) == False and not os.access(self.argsrun, os.X_OK):
            print("\033[31mCommand exception: Command %s" % self.runtime + " not found!\033[0m")
            sys.exit(127)
        elif os.path.isfile("configuration/" + self.runtime + "_config.py") == False:
            print("\033[31mConfiguration exception: No runtime configuration file found!\033[0m")
            sys.exit(128)

class Statistics:
    init_flag = False

    def __init__(self):
        if Statistics.init_flag:
            return

        self.fail = 0
        self.succ = 0
        self.ignore = 0
        
        Statistics.init_flag = True

    def addSucc(self, inc = 1):
        self.succ += inc

    def addFail(self, inc = 1):
        self.fail += inc

    def addIgnore(self, inc = 1):
        self.ignore += inc

class Runner:
    def __init__(self):
        
        configuration_dir = base_dir + '/configuration'
        sys.path.append(configuration_dir)
        self.commandline_parsing = commandline_parsing()
        runtime_cfg = self.commandline_parsing.runtime + "_config"
        config_module = __import__('configuration.' + runtime_cfg, fromlist = runtime_cfg)
        self.runtime_config = config_module.runtime_config()
        
        self.suite_config = None
        self.case_config = None
        self.workdir = "case/" + suite
        if not os.path.exists(self.workdir) and "standalone" in suite:
            self.workdir = "case/standalone/" + suite
        if not os.path.exists(self.workdir):
            self.workdir = "case/benchmark/" + suite
        self.statistics = Statistics()

    def getSuiteCases(self, suite):
        case_list = []
        
        for root, dirs, files in os.walk(self.workdir):
            files.sort()
            for file in files:
                if file.endswith(self.suite_config.casetype):
                    file = os.path.join(root, file)
                    dir_count = self.workdir.count("/", 4, len(self.workdir))
                    if suite == "issues":
                        casedirnum = dir_count + 2
                    else:
                        casedirnum = dir_count + 1
                    if casedirnum == file.count("/", 4, len(file)) or self.suite_config.type == "java":
                        case_list.append(file)
        return case_list

    def getfOption(self, cfg_bool):
        attribute_name = self.commandline_parsing.runtime + "_fOption"
        runtime_fOption = getattr(self.suite_config, attribute_name)
        case_fOption_bool = hasattr(self.case_config, "fOption")
        if runtime_fOption != "" and case_fOption_bool == True and cfg_bool == True:
            fOption = runtime_fOption + ' %s' %self.case_config.fOption
            func = self.case_config.func
        elif runtime_fOption != "":
            fOption = runtime_fOption
            func = self.suite_config.func
        elif cfg_bool == True and self.suite_config.fOption != "":
            fOption = self.suite_config.fOption
            func = self.case_config.func
        elif cfg_bool == True and case_fOption_bool == True:
            fOption = self.case_config.fOption
            func = self.case_config.func
        else:
            fOption = self.suite_config.fOption
            func = self.suite_config.func

        if cfg_bool == True and self.case_config.dir != "":
            fOption = self.case_config.dir + " %s" % fOption

        return fOption, func


    def getCaseargs(self, args):
        try:
            getattr(self.case_config, args)
            return getattr(self.case_config, args)
        except AttributeError as e:
            return getattr(self.suite_config, args)

    def getParams(self):
        if '>&' in self.case_config.parameter or self.case_config.parameter.startswith('|') == True or self.case_config.parameter.startswith('>'):
            fargsOptions = ""
            args_list = self.case_config.parameter
        elif " > " in self.case_config.parameter and self.runtime_config.args_list != "":
            fargsOptions = ""
            parameter_list = self.case_config.parameter.split(" >", 1)
            args_list = '--args ' + parameter_list[0] + ' > %s' %parameter_list[1]
        elif self.case_config.parameter != "":
            fargsOptions = self.runtime_config.fargsOptions
            args_list = self.case_config.parameter
        elif self.case_config.func == "":
            fargsOptions = ""
            args_list = self.suite_config.parameter
        else:
            fargsOptions = self.suite_config.fargsOptions
            args_list = self.suite_config.parameter

        return fargsOptions, args_list

    def runAllSuites(self):
        self.test_start = time.time()
        case_config_dir = base_dir + '/' + self.workdir
        sys.path.append(case_config_dir)

        suite_module = __import__(self.workdir.replace('/', '.') + ".config", fromlist = "config")
        self.suite_config = suite_module.SuiteConfig()

        if os.path.isfile(self.workdir + "/config.py") == False:
            print("\033[31mParameter exception: The suit parameter input is abnormal or the suit configuration file does not exist!\033[0m")
            sys.exit(2)

        expected = self.suite_config.expected
        self.case_num = len(self.getSuiteCases(suite))
        print("\n##################################  %s" % self.suite_config.testname + "TEST START  #####################################")
        for case_name in self.getSuiteCases(suite):
            configuration_file = case_name.rsplit('.', 1)[0] + "_config.py"
            cfg_bool = os.path.exists(configuration_file)
            args_list = self.suite_config.parameter
            command = self.commandline_parsing.argsrun

            if cfg_bool == True:
                case_cfg = configuration_file.rsplit('/', 1)[1].rsplit('.', 1)[0]
                workdir = self.workdir
                if "passed" in configuration_file:
                    workdir = self.workdir + "/passed"
                elif "notpass" in configuration_file:
                    workdir = self.workdir + "/notpass"

                if workdir.count("/", 4, len(workdir)) == 2:
                    case_module = __import__(workdir.replace('/', '.') + "." + case_cfg, fromlist = case_cfg)
                else:
                    case_module = __import__("case." + self.workdir.rsplit("/", 1)[1] + "." + case_cfg, fromlist = case_cfg)
                self.case_config = case_module.config()
                expected = self.case_config.expected
                func = self.case_config.func
                if self.suite_config.command != "":
                    command = "".join(self.suite_config.command).format(input_command = self.case_config.input_command, runtime = self.commandline_parsing.argsrun, memory_options = self.runtime_config.memory_options)
                fargsOptions, args_list = self.getParams()
                fOption, func = self.getfOption(cfg_bool)
            else:
                fOption, func = self.getfOption(cfg_bool)
                fargsOptions = self.suite_config.fargsOptions

            if 'workdir' in args_list:
                args_list = args_list.replace('workdir', self.workdir)
            self.runOneCase(command, fOption, func, case_name, fargsOptions, args_list, expected)

        self.info(self.statistics.succ, self.statistics.fail, self.statistics.ignore)

        ret_code = self.retCode(self.statistics.fail)
        if suite == "issues" or suite == "trophies":
            ret_code = 0
        return ret_code

    def getCommand(self):
        try:
            self.suite_config.command_template
            return self.suite_config.command_template
        except AttributeError as e:
            return self.runtime_config.command_template

    def getExpected(self, expected_bool, is_regex_expected, regex_file):

        if is_regex_expected == True:
            expected = self.runExpected(regex_file)
        elif expected_bool == True:
            expected = self.runExpected(regex_file)
        else:
            expected = "OFF"

        return expected

    def runExpected(self, expected_file):
        expected_str = open(expected_file, "r", encoding = "utf-8", errors = 'ignore').read()
        if expected_str != "" and expected_str[-1] == '\n':
            expected = expected_str[:expected_str.rfind('\n')]
        else:
            expected = expected_str
        return expected

    def sysRun(self, command, case_name):
        print("command: %s" % command)
        run_subprocess = subprocess.Popen(command, shell = True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = run_subprocess.communicate()
        self.return_code = run_subprocess.wait()
        self.result_str = output.decode('utf-8', "ignore")

    def removeNumbers(self, str):
        str = newstring = ''.join([i for i in str if not i.isdigit()])
        return str

    def checkExpected(self, wasm_name, result_str, expected, is_regex = False):
        result = result_str.rstrip(u'\x00').rstrip()
        expected = expected.rstrip(u'\x00').rstrip()

        if is_regex:
            findall = re.findall(expected, result)
            if findall:
                return True
        if result == expected:
            return True

        print("\nexpected: \n%s" % expected + "\n\nresult: \n%s" % result)

        return False
    
    def checkIgnore(self, ignore_case):
        universal_ignore = runtime_ignore = interp_ignore = ""
        ignore_case_bool = hasattr(self.suite_config, 'ignore_case')
        runtime_ignore_bool = hasattr(self.suite_config, self.commandline_parsing.runtime + '_ignore')
        interp_ignore_bool = hasattr(self.suite_config, 'interp_ignore')
        multipass_ignore_bool = hasattr(self.suite_config, 'multipass_ignore')
        dtvm_options = args.dtvm_options
        is_dtvm_interpreter = dtvm_options.find('-m 0') >= 0 or dtvm_options.find('-m interpreter') >= 0
        is_dtvm_singlepass = dtvm_options.find('-m 1') >= 0 or dtvm_options.find('-m singlepass') >= 0
        is_dtvm_multipass = dtvm_options.find('-m 2') >= 0 or dtvm_options.find('-m multipass') >= 0

        if ignore_case_bool == True and ignore_case in self.suite_config.ignore_case:
            return True
        if runtime_ignore_bool == True and ignore_case in getattr(self.suite_config, self.commandline_parsing.runtime + '_ignore'):
            return True
        if self.commandline_parsing.runtime == "dtvm":
            if is_dtvm_interpreter and interp_ignore_bool and ignore_case in self.suite_config.interp_ignore:
                return True
            if is_dtvm_multipass and multipass_ignore_bool and ignore_case in self.suite_config.multipass_ignore:
                return True
        return False

    def javaCheck(self, case_name):
        newcase = case_name.replace('$', '\$')
        if self.suite_config.type == 'java':
            ignore_case = newcase.split('/', 2)[2]
        else:
            ignore_case = case_name.rsplit('/', 1)[1]
        return newcase, ignore_case

    def formatCommandString(self, command_str):
        if command_str.startswith(':'):
            command_str = command_str.replace(': |', '')
        return command_str

    def mergeSpaces(self, string):
        words = string.split()
        merged_string = ' '.join(words)
        return merged_string

    def sysRunCheck(self, command_str, command, fOption, func, case_name, newcase, fargsOptions, args_list):
        command = self.formatCommandString(command)

        if suite == "gas-meter":
            fO_list = fOption.split(',')
            for op in fO_list:
                string = command_str.format(command = command, wasm_file = newcase, dtvm_options = args.dtvm_options, fOption = fOption, func = func, fargsOptions = fargsOptions, args_list = args_list)
                command = self.mergeSpaces(string)
                self.sysRun(command, case_name)
                if "1000000000" in self.result_str and "Exception: out of gas" not in self.result_str:
                    self.return_code = 1
                    break
                elif "35000000000" in self.result_str and "Exception: out of gas" in self.result_str:
                    self.return_code = 1
                    break
        else:
            string = command_str.format(command = command, wasm_file = newcase, dtvm_options = args.dtvm_options, fOption = fOption, func = func, fargsOptions = fargsOptions, args_list = args_list)
            command = self.mergeSpaces(string)
            self.sysRun(command, case_name)

    def runOneCase(self, command, fOption, func, case_name, fargsOptions, args_list, expected):
        case_start = time.time()
        command_str = self.getCommand()
        if self.runtime_config.memory_options != "":
            command_str = command_str.replace('{wasm_file}', '').replace('{fargsOptions}', '{wasm_file} {fargsOptions}')
        newcase, ignore_case = self.javaCheck(case_name)
        wasm_name = case_name.rsplit('/', 1)[1]
        workdir = os.path.dirname(case_name) + '/'
        expected_bool = os.path.exists(case_name + ".expected")
        case_regex = case_name + ".expected_regex"
        runtime_regex = workdir + self.commandline_parsing.runtime +  '_' + wasm_name + ".expected_regex"

        if os.path.exists(case_regex):
            is_regex_expected = True
            regex_file = case_regex
        elif os.path.exists(runtime_regex):
            is_regex_expected = True
            regex_file = runtime_regex
        else:
            is_regex_expected = False
            regex_file = case_name + ".expected"

        expected = self.getExpected(expected_bool, is_regex_expected, regex_file)

        if self.checkIgnore(ignore_case):
            print("test {:75} ........ \033[1;33m [IGNORE]\033[0m".format(case_name))
            self.statistics.addIgnore()
        else:
            print("testing {:72} ........ \033[1;32m \033[0m".format(case_name))
            self.sysRunCheck(command_str, command, fOption, func, case_name, newcase, fargsOptions, args_list)
            if expected != "OFF" and self.checkExpected(wasm_name, self.result_str, expected, is_regex_expected):
                print("test {:75} ........ \033[1;32m [PASSED]\033[0m".format(case_name))
                self.statistics.addSucc()
            elif self.return_code == 1 and self.checkExpected(wasm_name, self.result_str, expected, is_regex_expected):
                print("test {:75} ........ \033[1;32m [PASSED]\033[0m".format(case_name))
                self.statistics.addSucc()
            elif expected == "OFF" and self.return_code == 0:
                print("test {:75} ........ \033[1;32m [PASSED]\033[0m".format(case_name))
                self.statistics.addSucc()
            elif self.suite_config.type == "malformed" and not self.result_str.startswith("Segmentation fault"):
                print("test {:75} ........ \033[1;32m [PASSED]\033[0m".format(case_name))
                self.statistics.addSucc()
            elif "issues/notpass" in case_name and self.return_code != 0:
                print("test {:75} ........ \033[1;32m [PASSED]\033[0m".format(case_name))
                self.statistics.addSucc()
            elif 'Exception' in self.result_str:
                print("test {:75} ........ \033[1;31m [FAILED]\033[0m".format(case_name))
                self.statistics.addFail()
            else:
                print("test {:75} ........ \033[1;31m [FAILED]\033[0m".format(case_name))
                self.falseValidation(expected, wasm_name)
                self.statistics.addFail()

        case_end = time.time()
        current_number = self.statistics.succ + self.statistics.fail + self.statistics.ignore
        self.testprogress(current_number, self.case_num, case_start, case_end)

    def testprogress(self, current_number, total_number, case_start, case_end):
        Proportion = 100 * current_number / total_number
        print("Currently executed case: {}/{} ,Testing time-consuming: {:.3f} ms, The test progress is: {:.2f}%".format(current_number, total_number, (case_end - case_start) * 1000, Proportion))

    def info(self, succ_cnt, fail_cnt, ignore_cnt):
        test_end = time.time()

        print("\n##################################  %s" % self.suite_config.testname + "TEST END  #####################################")
        print("run {} test cases in {:.3f} ms, {} passed, {} ignore, {} failed"
        .format(succ_cnt + fail_cnt + ignore_cnt, (test_end - self.test_start) * 1000, succ_cnt, ignore_cnt, fail_cnt))

    def falseValidation(self, expected, wasm_name):
        if self.return_code == 0:
            print("\033[31mVerification exception: The result obtained by the test does not match the expected result, and the verification fails!\033[0m")
        else:
            print("\033[31mVerification exception: the status return value of the test command is not 0, verification failed!!\033[0m")
    
    def retCode(self, fail_cnt):
        if fail_cnt != 0:
            ret_code = 101
        else:
            ret_code = 0
        return ret_code

if __name__ == '__main__':
    for suite in args.suite_name:
        ret_code = Runner().runAllSuites()
        if ret_code != 0:
            sys.exit(ret_code)

        Statistics.init_flag = False
