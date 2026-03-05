// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmc/mocked_host.hpp>
#include "host/evm/crypto.h"
#include "tests/solidity_test_helpers.h"
#include "utils/evm.h"
#include <iostream>
#include <filesystem>

using namespace zen::evm_test_utils;
using namespace zen::utils;

// Custom EVMC Host that uses evmc::VM for execution, allowing recursive CALLs
class EVMCBenchmarkHost : public evmc::MockedHost {
    evmc::VM* Vm = nullptr;
    evmc_revision Rev = EVMC_CANCUN;

public:
    void SetVm(evmc::VM* VmParam) { Vm = VmParam; }
    void SetRevision(evmc_revision RevParam) { Rev = RevParam; }

    evmc::Result call(const evmc_message& Msg) noexcept override {
        // Record the access
        if (recorded_account_accesses.empty())
            recorded_account_accesses.reserve(200);
        if (recorded_account_accesses.size() < 200)
            recorded_account_accesses.emplace_back(Msg.recipient);

        if (Msg.kind == EVMC_CREATE || Msg.kind == EVMC_CREATE2) {
            evmc::address NewAddress;
            if (Msg.kind == EVMC_CREATE) {
                NewAddress = computeCreateAddress(Msg.sender, accounts[Msg.sender].nonce++);
            } else {
                accounts[Msg.sender].nonce++; // nonce is incremented for both CREATE and CREATE2
                
                std::vector<uint8_t> InitCode(Msg.input_data, Msg.input_data + Msg.input_size);
                std::vector<uint8_t> InitCodeHash = zen::host::evm::crypto::keccak256(InitCode);
                
                std::vector<uint8_t> Buffer;
                Buffer.reserve(1 + sizeof(Msg.sender.bytes) + sizeof(Msg.create2_salt.bytes) + InitCodeHash.size());
                Buffer.push_back(0xff);
                Buffer.insert(Buffer.end(), std::begin(Msg.sender.bytes), std::end(Msg.sender.bytes));
                Buffer.insert(Buffer.end(), std::begin(Msg.create2_salt.bytes), std::end(Msg.create2_salt.bytes));
                Buffer.insert(Buffer.end(), InitCodeHash.begin(), InitCodeHash.end());
                
                std::vector<uint8_t> FinalHash = zen::host::evm::crypto::keccak256(Buffer);
                std::copy_n(FinalHash.end() - sizeof(NewAddress.bytes), sizeof(NewAddress.bytes), NewAddress.bytes);
            }

            // Create a new message for execution with the computed recipient
            evmc_message ExecMsg = Msg;
            ExecMsg.recipient = NewAddress;
            ExecMsg.input_data = nullptr;
            ExecMsg.input_size = 0;

            // For CREATE, we execute the init code
            evmc::Result Result = Vm->execute(*this, Rev, ExecMsg, Msg.input_data, Msg.input_size);
            if (Result.status_code == EVMC_SUCCESS && Result.output_size > 0) {
                // Save the deployed code
                auto& Account = accounts[NewAddress];
                Account.code = evmc::bytes(Result.output_data, Result.output_size);
            }
            Result.create_address = NewAddress;
            return Result;
        } else {
            // Normal CALL
            auto It = accounts.find(Msg.recipient);
            if (It == accounts.end() || It->second.code.empty()) {
                // No code, just transfer value and return success
                return evmc::Result{EVMC_SUCCESS, Msg.gas, 0, nullptr, 0};
            }
            const auto& Code = It->second.code;
            return Vm->execute(*this, Rev, Msg, Code.data(), Code.size());
        }
    }
};

static std::unique_ptr<evmc::VM> GlobalVm;
static evmc_revision GlobalRev = EVMC_CANCUN;

static std::map<std::string, evmc::address> SetupHostFromContractTest(EVMCBenchmarkHost& Host, const SolidityContractTestData& ContractTest, uint64_t GasLimit) {
    evmc::address Deployer = parseAddress("1000000000000000000000000000000000000000");
    auto& DeployerAcc = Host.accounts[Deployer];
    DeployerAcc.nonce = 0;
    DeployerAcc.set_balance(100000000000ULL);

    // Precompute all contract addresses so forward references work
    std::map<std::string, evmc::address> ResolvedAddresses;
    for (size_t I = 0; I < ContractTest.DeployContracts.size(); ++I) {
        ResolvedAddresses[ContractTest.DeployContracts[I]] =
            computeCreateAddress(Deployer, I);
    }

    std::map<std::string, evmc::address> DeployedAddresses;

    for (const std::string& Name : ContractTest.DeployContracts) {
        auto It = ContractTest.ContractDataMap.find(Name);
        if (It == ContractTest.ContractDataMap.end()) {
            throw std::runtime_error("Contract data not found for: " + Name);
        }

        std::vector<std::pair<std::string, std::string>> CtorArgs;
        auto ArgsIt = ContractTest.ConstructorArgs.find(Name);
        if (ArgsIt != ContractTest.ConstructorArgs.end()) {
            CtorArgs = ArgsIt->second;
        }

        std::string DeployHex = It->second.DeployBytecode + encodeConstructorParams(CtorArgs, ResolvedAddresses);
        auto DeployBytecode = fromHex(DeployHex);
        if (!DeployBytecode) {
            throw std::runtime_error("Invalid hex for deployment of " + Name);
        }

        evmc::address ContractAddr = computeCreateAddress(Deployer, Host.accounts[Deployer].nonce);
        
        evmc_message Msg = {};
        Msg.kind = EVMC_CREATE;
        Msg.gas = GasLimit;
        Msg.recipient = ContractAddr;
        Msg.sender = Deployer;
        Msg.input_data = DeployBytecode->data();
        Msg.input_size = DeployBytecode->size();
        Msg.depth = 0;

        evmc::Result Res = GlobalVm->execute(Host, GlobalRev, Msg, DeployBytecode->data(), DeployBytecode->size());
        if (Res.status_code != EVMC_SUCCESS) {
            throw std::runtime_error("Deploy failed for " + Name + " status: " + std::to_string(Res.status_code));
        }

        if (Res.output_size > 0) {
            Host.accounts[ContractAddr].code = evmc::bytes(Res.output_data, Res.output_size);
        }

        Host.accounts[Deployer].nonce++;
        DeployedAddresses[Name] = ContractAddr;
    }
    return DeployedAddresses;
}

// Helper function to build calldata from a test case
static std::vector<uint8_t> BuildCalldata(const SolidityTestCase& Tc,
                                           const std::map<std::string, evmc::address>& Addrs) {
    // Currently, SolidityTestCase does not expose typed arguments; rely on raw calldata.
    (void)Addrs;  // unused until dynamic argument encoding is wired through SolidityTestCase
    if (!Tc.Calldata.empty()) {
        auto Opt = fromHex(Tc.Calldata);
        if (Opt) return *Opt;
    }
    return {};
}

class ContractBenchmark {
public:
    SolidityContractTestData ContractTest;
    SolidityTestCase TestCase;
    std::unique_ptr<EVMCBenchmarkHost> Host;
    evmc::address ContractAddress;
    std::vector<uint8_t> Calldata;
    std::map<std::string, evmc::address> DeployedAddresses;

    ContractBenchmark(const SolidityContractTestData& TestData, const SolidityTestCase& CaseData) 
        : ContractTest(TestData), TestCase(CaseData) {}

    void SetUp() {
        Host = std::make_unique<EVMCBenchmarkHost>();
        Host->SetVm(GlobalVm.get());
        Host->SetRevision(GlobalRev);

        DeployedAddresses = SetupHostFromContractTest(*Host, ContractTest, 0xFFFFFFFFFFFF);

        evmc::address Deployer = parseAddress("1000000000000000000000000000000000000000");

        // Run setup test cases (name starts with "setup_")
        for (const auto& SetupTc : ContractTest.TestCases) {
            if (SetupTc.Name.rfind("setup_", 0) != 0) continue;
            auto SetupCd = BuildCalldata(SetupTc, DeployedAddresses);
            if (SetupCd.empty()) continue;

            evmc::address Target = DeployedAddresses[SetupTc.Contract];
            evmc_message SetupMsg = {};
            SetupMsg.kind = EVMC_CALL;
            SetupMsg.gas = 0xFFFFFFFFFFFF;
            SetupMsg.recipient = Target;
            SetupMsg.sender = Deployer;
            SetupMsg.input_data = SetupCd.data();
            SetupMsg.input_size = SetupCd.size();
            GlobalVm->execute(*Host, GlobalRev, SetupMsg,
                               Host->accounts[Target].code.data(),
                               Host->accounts[Target].code.size());
        }

        ContractAddress = DeployedAddresses[TestCase.Contract];
        Calldata = BuildCalldata(TestCase, DeployedAddresses);
    }

    void TearDown() {
        Host.reset();
    }
};

static void RegisterBenchmarks() {
    std::filesystem::path TestsRoot = "tests/evm_solidity";
    if (!std::filesystem::exists(TestsRoot)) {
        TestsRoot = "../tests/evm_solidity";
    }
    
    std::vector<std::string> Categories = {"defi", "erc20_bench", "nft", "dao", "layer2"};

    for (const auto& Cat : Categories) {
        std::filesystem::path CatDir = TestsRoot / Cat;
        if (!std::filesystem::exists(CatDir)) continue;

        ContractDirectoryInfo DirInfo = checkCaseDirectory(CatDir);
        if (!std::filesystem::exists(DirInfo.SolcJsonFile) || !std::filesystem::exists(DirInfo.CasesFile)) continue;

        SolidityContractTestData ContractTest;
        parseContractJson(DirInfo.SolcJsonFile, ContractTest.ContractDataMap);
        parseTestCaseJson(DirInfo.CasesFile, ContractTest);

        for (const auto& Tc : ContractTest.TestCases) {
            if (Tc.Name.rfind("setup_", 0) == 0) continue;

            std::string BenchName = Cat + "/" + Tc.Name;
            
            // We use lambda to capture test data
            benchmark::RegisterBenchmark(BenchName.c_str(), [ContractTest, Tc](benchmark::State& State) {
                ContractBenchmark Fixture(ContractTest, Tc);
                Fixture.SetUp();

                evmc_message Msg = {};
                Msg.kind = EVMC_CALL;
                Msg.gas = 0xFFFFFFFFFFFF;
                Msg.recipient = Fixture.ContractAddress;
                Msg.sender = parseAddress("1000000000000000000000000000000000000000");
                Msg.input_data = Fixture.Calldata.data();
                Msg.input_size = Fixture.Calldata.size();

                // Warm-up: trigger JIT compilation outside timed loop
                {
                    // Save host state so warm-up does not affect benchmark iterations
                    auto SavedAccounts = Fixture.Host->accounts;

                    const auto& Code = Fixture.Host->accounts[Fixture.ContractAddress].code;
                    auto Warmup = GlobalVm->execute(*Fixture.Host, GlobalRev, Msg, Code.data(), Code.size());
                    benchmark::DoNotOptimize(Warmup);

                    // Restore host state to ensure clean, reproducible benchmark runs
                    Fixture.Host->accounts = std::move(SavedAccounts);
                }

                for (auto _ : State) {
                    const auto& Code = Fixture.Host->accounts[Fixture.ContractAddress].code;
                    evmc::Result Res = GlobalVm->execute(*Fixture.Host, GlobalRev, Msg, Code.data(), Code.size());
                    benchmark::DoNotOptimize(Res);
                }

                Fixture.TearDown();
            })->Unit(benchmark::kMicrosecond);
        }
    }
}

int main(int Argc, char** Argv) {
    // Parse our custom args before benchmark::Initialize
    std::string VmConfig;

    std::vector<char*> BArgv;
    BArgv.push_back(Argv[0]);

    for (int I = 1; I < Argc; ++I) {
        std::string Arg = Argv[I];
        if (Arg == "--vm" && I + 1 < Argc) {
            VmConfig = Argv[++I];
        } else {
            BArgv.push_back(Argv[I]);
        }
    }
    
    int BArgc = static_cast<int>(BArgv.size());
    benchmark::Initialize(&BArgc, BArgv.data());

    if (!VmConfig.empty()) {
        evmc_loader_error_code Ec;
        evmc::VM Vm{evmc_load_and_configure(VmConfig.c_str(), &Ec)};
        if (Ec != EVMC_LOADER_SUCCESS) {
            std::cerr << "Failed to load EVMC VM from " << VmConfig << "\n";
            return 1;
        }
        GlobalVm = std::make_unique<evmc::VM>(std::move(Vm));
    } else {
        std::cerr << "Usage: " << Argv[0] << " --vm <path_to_so> [benchmark_options]\n";
        return 1;
    }

    RegisterBenchmarks();
    return benchmark::RunSpecifiedBenchmarks();
}
