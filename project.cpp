/*########################################################################################################*/
// cd /nfs/iil/ptl/bt/ghaber1/pin/pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux/source/tools/SimpleExamples
// make
//  ../../../pin -t obj-intel64/print-probe.so -- ~/workdir/tst
/*########################################################################################################*/
/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/* ===================================================================== */

/* ===================================================================== */
/*! @file
 * This probe pintool prints out the disassembled instructions of a given exec file.
 */

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}

// CSV Defines
#define CSV_RTN_ADDR 1
#define CSV_RTN_NAME 2
#define CSV_NUM_CALLERS_TO_ROUTINE 3
#define CSV_NUM_CALLER_CALLS 4
#define CSV_NUM_RETS_INS 5
#define CSV_DIRECT_JUMPS_OUT 6
#define CSV_INDIRECT_BRANCHES 7
#define CSV_CALLER_INS_ADDRESS 8
#define CSV_CALLER_RTN_ADDR 9
#define CSV_BAD_RBP_RSP_OFFSET 10
#define CSV_RET_IS_LAST_INST 11
#define CSV_DIRECT_JUMP_TO_CALLEE 12
#define CSV_CALL_TO_MIDDLE_OF_RTN 13
#define CSV_BBLS 14

#define CSV_FILE "profile.csv"

// Include
#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <list>
#include <malloc.h>
#include <map>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>
#include <string>
#include <set>
#include <unistd.h>
#include <values.h>
#include <vector>

using namespace std;

/*======================================================================*/
/* Commandline Switches                                                 */
/*======================================================================*/

KNOB<BOOL> KnobProf(KNOB_MODE_WRITEONCE, "pintool",
	"prof", "0", "JIT run");

KNOB<BOOL> KnobOpt(KNOB_MODE_WRITEONCE, "pintool",
	"opt", "0", "Probe run");

KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL> KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL> KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

KNOB<BOOL> KnobNoInline(KNOB_MODE_WRITEONCE, "pintool",
    "no_inline", "0", "Do not perform inline");

KNOB<BOOL> KnobNoReorder(KNOB_MODE_WRITEONCE, "pintool",
    "no_reorder", "0", "Do not perform reorder");

KNOB<BOOL> KnobCC1Enable(KNOB_MODE_WRITEONCE, "pintool",
    "cc1_enable", "0", "Use to optimize cc1");

KNOB<INT> KnobCall(KNOB_MODE_WRITEONCE, "pintool",
    "call", "100", "Threshold - Number of calls to callee");

KNOB<INT> KnobBbl(KNOB_MODE_WRITEONCE, "pintool",
    "bbls", "2", "Threshold - Number of bbls in routine");

KNOB<string> KnobFile(KNOB_MODE_WRITEONCE, "pintool",
	 "f", CSV_FILE, "CSV file");

/* ===================================================================== */
/* Print Help Message */
/* ===================================================================== */

INT32 Usage() {
    cerr <<
        "Project 2023\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;

    return -1;
}

/* ===================================================================== */
/* ===================================================================== */
/* ===================================================================== */
/* PROF PROF PROF PROF PROF PROF PROF PROF PROF PROF PROF PROF PROF PROF */
/* ===================================================================== */
/* ===================================================================== */
/* ===================================================================== */

/* ===================================================================== */
/* Classes */
/* ===================================================================== */

class CALL_INFO {
	public:
        ADDRINT target_address; // rtn_map : key
		ADDRINT call_ins_address;
		ADDRINT caller_rtn_address;
        UINT64 num_callers_to_rtn;
		bool jump_to_callee_rtn;
		bool jump_to_middle_of_rtn;
		bool call_to_middle_of_rtn;

    CALL_INFO(ADDRINT rtn_address, ADDRINT ins_address, ADDRINT caller_rtn_address, bool call_to_middle_of_rtn) {
        this->target_address = rtn_address;
		this->call_ins_address = ins_address;
		this->caller_rtn_address = caller_rtn_address;
        this->num_callers_to_rtn = 0;
		this->jump_to_callee_rtn = false;
		this->jump_to_middle_of_rtn = false;
		this->call_to_middle_of_rtn = call_to_middle_of_rtn;
    }
};

class JUMP_INFO {
	public:
		ADDRINT target_address;
		ADDRINT target_rtn_address;
		bool jump_to_middle_of_routine;

    JUMP_INFO(ADDRINT target_address, ADDRINT target_rtn_address) {
        this->target_address = target_address;
		this->target_rtn_address = target_rtn_address;
		this->jump_to_middle_of_routine = (target_address != target_rtn_address);
    }
};

class RTN_INFO {
    public:
		// CALLEE
		string rtn_name;
		UINT64 num_callers_to_rtn;
		string num_caller_calls;
		UINT32 num_static_ins;
		UINT32 num_ret_ins;
		bool direct_jumps_out;
		bool indirect_branches;
		string caller_ins_address;
		string caller_rtn_address;
		bool bad_rsp_rbp_offset;
		bool ret_is_last_inst;
        UINT64 rtn_count;
		bool multiple_ret_ins;
		bool negative_disp;
		ADDRINT ret_addr;
		bool call_to_middle_of_rtn;
		// CALLER
		bool jump_to_callee_rtn;
		bool jump_to_middle_of_rtn; 
		
    RTN_INFO(string rtn_name, UINT32 ins_num) {
		// CALLEE
		this->rtn_name = rtn_name;
		this->num_callers_to_rtn = 0;
		this->num_caller_calls = "";
		this->num_static_ins = ins_num;
		this->num_ret_ins = 0;
		this->direct_jumps_out = false;
		this->indirect_branches = false;
		this->caller_ins_address = "";
		this->caller_rtn_address = "";
		this->bad_rsp_rbp_offset = false;
		this->ret_is_last_inst = false;
        this->rtn_count = 0;
		this->multiple_ret_ins = false;
		this->negative_disp = false;
		this->ret_addr = 0;
		this->call_to_middle_of_rtn = false;
		// CALLER
		this->jump_to_callee_rtn = false;
		this->jump_to_middle_of_rtn = false;
    }
};

/* ===================================================================== */
/* Structs */
/* ===================================================================== */

typedef struct bbl_info {
    ADDRINT head_address;
    ADDRINT tail_address;
    bool tail_is_conditional_jump;
	ADDRINT rtn_address;
	UINT64 jump_count;
	UINT64 ft_count;
} BBL_INFO;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

map<ADDRINT, BBL_INFO> bbl_map; 
map<ADDRINT, RTN_INFO> rtn_map;
map<ADDRINT, CALL_INFO> call_map;
vector<JUMP_INFO> jumps_outside_function;

/* ===================================================================== */
/* Count Functions */
/* ===================================================================== */

void docount_bbl(INT32 is_taken, BBL_INFO *info) { 
	if (is_taken)
        info->jump_count++;
    else
        info->ft_count++;
}

void docount_call(CALL_INFO *call) {
    call->num_callers_to_rtn++;
}

void docount_rtn(RTN_INFO *rtn) {
    rtn->rtn_count++;
}

/* ===================================================================== */
/* Sort Functions */
/* ===================================================================== */

bool sort_bbl(const BBL_INFO* a, const BBL_INFO* b) { 
    return (a->head_address < b->head_address); 
}

bool sort_rtn(const pair<ADDRINT, RTN_INFO>& a, const pair<ADDRINT, RTN_INFO>& b) {
    return a.second.rtn_count > b.second.rtn_count;
}

/* ===================================================================== */
/* BBL Functions */
/* ===================================================================== */

bool is_bbl_in_map(ADDRINT bbl_address) {
    return bbl_map.find(bbl_address) != bbl_map.end();
}

void add_bbl_to_map(BBL bbl) {  
    INS bbl_tail = BBL_InsTail(bbl);
    
    // Create BBL info
    BBL_INFO info;
    info.tail_address = INS_Address(bbl_tail);
    info.head_address = INS_Address(BBL_InsHead(bbl));
	info.rtn_address = RTN_Address(RTN_FindByAddress(info.tail_address));    
    info.jump_count = 0;
	info.ft_count = 0;
    info.tail_is_conditional_jump = INS_Category(bbl_tail) == XED_CATEGORY_COND_BR;
   
    // Add BBL info to map
	bbl_map[info.head_address] = info;  
}

void add_bbls_to_rtn(ADDRINT rtn_addr, vector<BBL_INFO*> *rtn_bbls) {   
    auto bbl_it = bbl_map.begin();
	
	// Iterate over all BBLs
	while (bbl_it != bbl_map.end()) {
        ADDRINT bbl_rtn_address = bbl_it->second.rtn_address;
        if (bbl_rtn_address == rtn_addr) // BBL belongs to routine
            rtn_bbls->push_back(&(bbl_it->second));
        bbl_it++;
    }
	
	// Sort BBLs by address
	sort(rtn_bbls->begin(), rtn_bbls->end(), sort_bbl);
}

/* ===================================================================== */
/* Instrument Functions */
/* ===================================================================== */

void Trace(TRACE trace, void *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {       
        if (!BBL_Valid(bbl))
            continue;
        
        INS tail = BBL_InsTail(bbl);
        if (INS_Valid(tail) == false)
            continue;
        
        ADDRINT tail_address = INS_Address(tail);
        
        RTN rtn = RTN_FindByAddress(tail_address);    
        if (RTN_Valid(rtn) == false)
            continue;
        
        IMG img = IMG_FindByAddress(tail_address);
        if (IMG_Valid(img) == false)
            continue;
        
        if (IMG_IsMainExecutable(img) == false)
            continue;

        ADDRINT head_address = INS_Address(BBL_InsHead(bbl));
        if (!is_bbl_in_map(head_address)) {
            if (KnobVerbose)
                cout << "Add BBL (" << hex << head_address << ", " << tail_address << ")" << endl;
               
            add_bbl_to_map(bbl);
        }
		
		BBL_INFO* current_bbl = &(bbl_map[head_address]);
		if (current_bbl->tail_is_conditional_jump) {
			// Count T/NT branches
			INS_InsertCall(tail,
						   IPOINT_BEFORE, 
						   (AFUNPTR)docount_bbl, 
						   IARG_BRANCH_TAKEN,                 
						   IARG_PTR, current_bbl,
						   IARG_END);     
		}
    }
}

void Routine(RTN rtn, void *v) {
	if (!RTN_Valid(rtn))
		return;

	SEC sec = RTN_Sec(rtn);
	if (!SEC_Valid(sec))
		return;
	
	IMG img = SEC_Img(sec);

	if (!IMG_Valid(img))
		return;

	if (!IMG_IsMainExecutable(img))
		return;
	
	RTN_Open(rtn);
	ADDRINT rtn_address = RTN_Address(rtn);	
	string rtn_name = RTN_Name(rtn);
	
	// Add new routine to map  
	UINT32 num_ins = RTN_NumIns(rtn);
	auto it = rtn_map.find(rtn_address);
	if (it == rtn_map.end()) {
		RTN_INFO rtn_info(rtn_name, num_ins);
		it = rtn_map.insert(pair<ADDRINT, RTN_INFO>(rtn_address, rtn_info)).first;
	}
	
	UINT32 num_static_ins = 0;
	
	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
		// Count static number of instructions in routine
		num_static_ins++;
		
		ADDRINT ins_address = INS_Address(ins);
		
		if (INS_IsControlFlow(ins)) {
			// Instruction is direct call: candidate for inline
			if (INS_IsCall(ins) && INS_IsDirectControlFlow(ins)) { 
				// Add new call to map  
				auto call_it = call_map.find(ins_address);
				if (call_it == call_map.end()) {
					ADDRINT target_address = INS_DirectControlFlowTargetAddress(ins);
					RTN target_rtn = RTN_FindByAddress(target_address);
					if (RTN_Valid(target_rtn)) {
						ADDRINT target_rtn_address = RTN_Address(target_rtn);
						CALL_INFO call_info(target_address, ins_address, rtn_address, (target_rtn_address != target_address));
						call_it = call_map.insert(pair<ADDRINT, CALL_INFO>(ins_address, call_info)).first;
					}
				}
				
				// Count number of times call was executed
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_call, IARG_PTR, &(call_it->second), IARG_END);
			}
			
			// Instruction is direct branch
			if (!INS_IsCall(ins) && INS_IsDirectControlFlow(ins)) {
				ADDRINT target_address = INS_DirectControlFlowTargetAddress(ins);
				string target_rtn_name = RTN_FindNameByAddress(target_address);
				// Add jump outside of current routine
				if (target_rtn_name != it->second.rtn_name) {
					it->second.direct_jumps_out = true;
					RTN target_rtn = RTN_FindByAddress(target_address);
					if (RTN_Valid(target_rtn)) {
						ADDRINT target_rtn_address = RTN_Address(target_rtn);
						jumps_outside_function.push_back(JUMP_INFO(target_address, target_rtn_address));
					}
				}
			}
			
			// Instruction is indirect branch
			if (INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins))
				it->second.indirect_branches = true;
		}
		
		// Instruction is not the last return
		if (INS_IsRet(ins) && it->second.ret_addr != ins_address) {
			it->second.num_ret_ins++;
			it->second.ret_addr = ins_address;
			if (num_ins == num_static_ins)
				it->second.ret_is_last_inst = true;
		}
		
		// Instruction is the last return
		// Count number of times routine was executed
		if (ins_address == rtn_address) 
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_PTR, &(it->second), IARG_END);

		// Check if routine has bad RSP RBP usage (not to inline)
		if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
			UINT32 mem_operands = INS_MemoryOperandCount(ins);
			for (UINT32 mem_op = 0; mem_op < mem_operands; mem_op++) {
				if (INS_MemoryOperandIsRead(ins, mem_op) || INS_MemoryOperandIsWritten(ins, mem_op)) {
					REG base_reg = INS_MemoryBaseReg(ins);
					INT32 displacement = INS_MemoryDisplacement(ins);
					if (base_reg == REG_RSP && displacement < 0) 
						it->second.bad_rsp_rbp_offset = true;
					
					if (base_reg == REG_RBP && displacement > 0) 
						it->second.bad_rsp_rbp_offset = true;
				}
			}
		}
    }
	
	RTN_Close(rtn);
}

/* ===================================================================== */
/* Fini */
/* ===================================================================== */

void add_jump_info_to_call() {
	// Iterate over calls
	for (auto& call : call_map) {
        CALL_INFO& info = call.second;
		// Iterate over jumps
		for (const auto& jump : jumps_outside_function) {
			// Direct jump and call to the same function
			if (jump.target_address == info.target_address) 
				info.jump_to_callee_rtn = true;

			info.jump_to_middle_of_rtn = jump.jump_to_middle_of_routine;
		}
    }
}

void add_call_info_to_rtn() {
	// Iterate over calls
	for (auto& call : call_map) {
		CALL_INFO& call_info = call.second;
		if (call_info.num_callers_to_rtn) {
			// Find routine (callee/hot)
			auto rtn_it = rtn_map.find(call_info.target_address);
    		if (rtn_it != rtn_map.end()) {
				RTN_INFO& rtn_info = rtn_it->second;
				// Callee / Hot routine
				rtn_info.num_callers_to_rtn++;
				rtn_info.num_caller_calls += to_string(call_info.num_callers_to_rtn) + ".";
				rtn_info.caller_ins_address += to_string(call_info.call_ins_address) + ".";
				rtn_info.caller_rtn_address += to_string(call_info.caller_rtn_address) + ".";
				// Caller
				rtn_info.jump_to_callee_rtn = call_info.jump_to_callee_rtn;
				rtn_info.jump_to_middle_of_rtn = call_info.jump_to_middle_of_rtn;
				rtn_info.call_to_middle_of_rtn = call_info.call_to_middle_of_rtn;
			}
		}
    }
}

void Fini(INT32 code, void *v) {  
    ofstream out_file(KnobFile.Value().c_str());
	
	// Merge jumps with calls
    add_jump_info_to_call();
	
	// Merge calls and rtns
    add_call_info_to_rtn();
   
    // Convert map to vector
    vector<pair<ADDRINT, RTN_INFO>> rtn_vec(rtn_map.begin(), rtn_map.end());
    
    // Sort in descending order
    sort(rtn_vec.begin(), rtn_vec.end(), sort_rtn);
    
	// Headers
    out_file << "CALLEE: rtn address" << ","
			 << "CALLEE: rtn name" << ","
			 << "CALLER: # callers to rtn" << ","
			 << "CALLER: # callers' calls" << ","
			 << "CALLEE: # return ins" << ","
			 << "CALLEE: # direct jumps out" << ","
			 << "CALLEE: # indirect branches" << ","
			 << "CALLER: ins address" << ","
			 << "CALLER: rtn address" << ","
			 << "CALLEE: bad rsp/rbp offset" << ","
			 << "CALLEE: ret is last inst" << ","
			 << "CALLER: direct jump to callee" << ","
			 << "CALLEE: call to middle of rtn" << ","
			 << "CALLEE: BBL: head address" << ","
			 << "CALLEE: BBL: tail address" << ","
			 << "CALLEE: BBL: T > NT"
		 	 << "\n";

	// Routines 
	for (auto& pair : rtn_vec) {
		RTN_INFO& rtn_info = pair.second;
		
        if (rtn_info.rtn_count && rtn_info.num_callers_to_rtn) {
            rtn_info.num_caller_calls.pop_back();
            rtn_info.caller_ins_address.pop_back();
            rtn_info.caller_rtn_address.pop_back();
		
			out_file << hex << showbase << pair.first << ","
			  		 << rtn_info.rtn_name << ","
				 	 << dec
					 << rtn_info.num_callers_to_rtn << ","
				 	 << rtn_info.num_caller_calls << ","
					 << rtn_info.num_ret_ins << ","
					 << rtn_info.direct_jumps_out << ","
					 << rtn_info.indirect_branches << ","
					 << rtn_info.caller_ins_address << ","
					 << rtn_info.caller_rtn_address << ","
					 << rtn_info.bad_rsp_rbp_offset << ","
					 << rtn_info.ret_is_last_inst << ","
					 << rtn_info.jump_to_callee_rtn << ","
					 << rtn_info.call_to_middle_of_rtn;

			// BBLs
			vector<BBL_INFO*> rtn_bbls;
			add_bbls_to_rtn(pair.first, &rtn_bbls);
			ADDRINT last_tail = 0;
            for (auto bbl_it = rtn_bbls.begin(); bbl_it != rtn_bbls.end(); bbl_it++) {
				if (last_tail == (*bbl_it)->tail_address) // Avoid nested BBLs
					continue;
				last_tail = (*bbl_it)->tail_address;
				
				out_file << "," << hex << (*bbl_it)->head_address
						 << "," << (*bbl_it)->tail_address
						 << "," << dec << ((*bbl_it)->jump_count > (*bbl_it)->ft_count);
            }

            out_file << "\n";
        }
    }
	
    out_file.close();
}

/* ===================================================================== */
/* ===================================================================== */
/* ===================================================================== */
/* OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT OPT O */
/* ===================================================================== */
/* ===================================================================== */
/* ===================================================================== */

/* ===================================================================== */
/* Classes */
/* ===================================================================== */

class EXTRACTED_BBL_INFO {
    public:
		vector<INS> instructions;
		ADDRINT head_address;
		ADDRINT tail_address;
		ADDRINT jump_address;
		ADDRINT ft_address;
		bool has_conditonal_jump;
		bool jump_greater_ft;
		bool revert_jump;
		bool inserted_to_map;
		bool new_ft_of_higher_id;
		bool is_hot;
		bool tail_direct_call;
		bool is_indirect_jmp;
		bool is_regaular_cmd;
		int bbl_id;
		int bbl_ft_id;
		int bbl_jump_id;
		int bbl_next_id; // Unconditional jump: JUMP BBL; Conditional jump: FT BBL
		
	EXTRACTED_BBL_INFO() = default;
    EXTRACTED_BBL_INFO(vector<INS> instructions, ADDRINT head_address, ADDRINT tail_address, ADDRINT jump_address, ADDRINT ft_address, bool has_conditonal_jump, bool jump_greater_ft, bool tail_direct_call, bool is_indirect_jmp, bool is_regaular_cmd) {
        this->instructions = instructions;
		this->head_address = head_address;
		this->tail_address = tail_address;
		this->jump_address = jump_address;
		this->ft_address = ft_address;
		this->has_conditonal_jump = has_conditonal_jump;
		this->jump_greater_ft = jump_greater_ft;
		this->revert_jump = false;
		this->inserted_to_map = false;
		this->new_ft_of_higher_id = false;
		this->is_hot = false;
		this->tail_direct_call = tail_direct_call;
		this->is_indirect_jmp =  is_indirect_jmp;
		this->is_regaular_cmd = is_regaular_cmd;
		this->bbl_id = 0;
		this->bbl_ft_id = 0;
		this->bbl_jump_id = 0;
		this->bbl_next_id = 0;
    }
};

class DELETED_INS {
    public:
        ADDRINT address;
        ADDRINT next_address;
		
    DELETED_INS(ADDRINT address, ADDRINT next_address) {
        this->address = address;
        this->next_address = next_address;
    }
};

class INLINE_FUNCTION_INFO {
    public:
        ADDRINT callee_rtn_address; // Ins address of inline routine
        ADDRINT call_ins_address; // Ins address of call to inline routine
		vector<BBL_INFO> rtn_bbls;
		
	INLINE_FUNCTION_INFO() = default;
    INLINE_FUNCTION_INFO(ADDRINT rtn_address, ADDRINT caller_ins_address, vector<BBL_INFO>& rtn_bbls) {
        this->callee_rtn_address = rtn_address;
        this->call_ins_address = caller_ins_address;
		this->rtn_bbls = rtn_bbls;
    }
};

class INSERT_INLINE_INFO {
    public:
		int bbl_id;
        INLINE_FUNCTION_INFO info;
        ADDRINT address;
		
    INSERT_INLINE_INFO(int bbl_id, INLINE_FUNCTION_INFO& info, ADDRINT address) {
        this->bbl_id = bbl_id;
		this->info = info;
        this->address = address;
    }
};			

class TRANSLATED_RTN_INFO {
    public:
        vector<INLINE_FUNCTION_INFO> inline_functions;
        bool has_inline_function;
        bool is_inline_function;
		vector<BBL_INFO> rtn_bbls;
	
	TRANSLATED_RTN_INFO() = default;
    TRANSLATED_RTN_INFO(ADDRINT rtn_address, ADDRINT caller_ins_address, bool has_inline_function, bool is_inline_function, vector<BBL_INFO> &rtn_bbls) {
        if (has_inline_function)
            this->inline_functions.push_back(INLINE_FUNCTION_INFO(rtn_address, caller_ins_address, rtn_bbls));
        else
			this->rtn_bbls = rtn_bbls;
			
        this->has_inline_function = has_inline_function;
        this->is_inline_function = is_inline_function;
    }
	
    void add_inline_function(INLINE_FUNCTION_INFO info, bool is_inline_function) {
        this->has_inline_function = true;
        this->inline_functions.push_back(info);
        this->is_inline_function = is_inline_function;
    }
};

/* ===================================================================== */
/* Structs */
/* ===================================================================== */

// Instruction map with an entry for each new instruction:
typedef struct { 
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int targ_map_entry;
} instr_map_t;

// Tables of all candidate routines to be translated:
typedef struct { 
	ADDRINT rtn_addr; 
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;	
} translated_rtn_t;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

// For XED: Pass in the proper length: 15 is the max. But if you do not want to
// cross pages, you can pass less than 15 bytes, of course, the
// instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;	
int tc_cursor = 0;

instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;

// Total number of routines in the main executable module:
int max_rtn_count = 0;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;

map<ADDRINT, TRANSLATED_RTN_INFO> translated_rtn_map; // Hot routines & functions to inline
vector<ADDRINT> inline_routines_vec;

/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

void dump_all_image_instrs(IMG img)
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			// Open the RTN.
            RTN_Open( rtn );

			cerr << RTN_Name(rtn) << ":" << endl;

			for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {				
	              cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			}

			// Close the RTN.
            RTN_Close( rtn );
		}
	}
}

void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
	// debug print decoded instr:
	char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime adddress for disassembly 	

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);	

    cerr << hex << address << ": " << disasm_buf <<  endl;
}

void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cout << "invalid opcode" << endl;
	  return;
  }
 
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cout << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;  
 
}

void dump_entire_instr_map()
{	
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {

				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cout << "Unknwon"  << ":" << endl;
				} else {
				  cout << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		/*
			ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;*/
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);		
	}
}

void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].targ_map_entry >= 0)
		new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
	else
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}

void dump_tc()
{
	char disasm_buf[2048];
	xed_decoded_inst_t new_xedd;
	ADDRINT address = (ADDRINT)&tc[0];
	unsigned int size = 0;
	// cerr<< "DUMP_TC DEBUG:"<<(ADDRINT)&tc[tc_cursor]<< endl;
 	while (address < (ADDRINT)&tc[tc_cursor]) {
		address += size;

		xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 

		xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

		BOOL xed_ok = (xed_code == XED_ERROR_NONE);
		if (!xed_ok){
			cerr << "invalid opcode" << endl;
			return;
		}

		xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

		cout << "0x" << hex << address << ": " << disasm_buf <<  endl;

		size = xed_decoded_inst_get_length (&new_xedd);	
  }
}

/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */

int chain_all_direct_br_and_call_target_entries()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {			    
		if (instr_map[i].orig_targ_addr == 0)
			continue;

		if (instr_map[i].hasNewTargAddr)
			continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
			   continue;
	
            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {                
		instr_map[i].hasNewTargAddr = true; 
	            instr_map[i].targ_map_entry = j;
                break;
			}
		}
	}
   
	return 0;
}

int fix_rip_displacement(int instr_map_entry) 
{
	//debug print:
	//dump_instr_map_entry(instr_map_entry);

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

	if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
		return 0;

	//cerr << "Memory Operands" << endl;
	bool isRipBase = false;
	xed_reg_enum_t base_reg = XED_REG_INVALID;
	xed_int64_t disp = 0;
	for(unsigned int i=0; i < memops ; i++)   {

		base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
		disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

		if (base_reg == XED_REG_RIP) {
			isRipBase = true;
			break;
		}
		
	}

	if (!isRipBase)
		return 0;

			
	//xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
	xed_int64_t new_disp = 0;
	xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

	unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

	// modify rip displacement. use direct addressing mode:	
	new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
	xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

	//Set the memory displacement using a bit length 
	xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;
			
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);
	
	xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry); 
		return -1;
	}				

	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}

int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}
	
	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {

		cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: " 
			  << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	// check for cases of direct jumps/calls back to the orginal target address:
	if (instr_map[instr_map_entry].targ_map_entry >= 0) {
		cerr << "ERROR: Invalid jump or call instruction" << endl;
		return -1;
	}

	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
				

	xed_encoder_instruction_t  enc_instr;

	ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
		               instr_map[instr_map_entry].new_ins_addr - 
					   xed_decoded_inst_get_length (&xedd);

	if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

	if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


	xed_encoder_request_t enc_req;

	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}
   

	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
	    dump_instr_map_entry(instr_map_entry); 
        return -1;
    }

	// handle the case where the original instr size is different from new encoded instr:
	if (olen != xed_decoded_inst_get_length (&xedd)) {
		
		new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
	               instr_map[instr_map_entry].new_ins_addr - olen;

		if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok) {
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}

		xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			dump_instr_map_entry(instr_map_entry);
			return -1;
		}		
	}

	
	// debug prints:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry); 
	}
		
	instr_map[instr_map_entry].hasNewTargAddr = true;
	return olen;	
}

int fix_direct_br_call_displacement(int instr_map_entry) 
{					

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	xed_int32_t  new_disp = 0;	
	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;


	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: unrecognized branch displacement" << endl;
		return -1;
	}

	// fix branches/calls to original targ addresses:
	if (instr_map[instr_map_entry].targ_map_entry < 0) {
	   int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
	   return rc;
	}

	ADDRINT new_targ_addr;		
	new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
		
	new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

	xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

	// the max displacement size of loop instructions is 1 byte:
	xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
	if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
	  new_disp_byts = 1;
	}

	// the max displacement size of jecxz instructions is ???:
	xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
	if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
	  new_disp_byts = 1;
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

	xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
	unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    
	xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
		char buf[2048];		
		xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
	    cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
  		return -1;
	}		

	new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

	new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);
	
	xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}				

	//debug print of new instruction in tc:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}				

int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;	

	do {
		
		size_diff = 0;

		if (KnobVerbose) {
			cerr << "starting a pass of fixing instructions displacements: " << endl;
		}

		for (int i=0; i < num_of_instr_map_entries; i++) {

			instr_map[i].new_ins_addr += size_diff;
				   
			int new_size = 0;

			// fix rip displacement:			
			new_size = fix_rip_displacement(i);
			if (new_size < 0)
				return -1;

			if (new_size > 0) { // this was a rip-based instruction which was fixed.

				if (instr_map[i].size != (unsigned int)new_size) {
				   size_diff += (new_size - instr_map[i].size); 					
				   instr_map[i].size = (unsigned int)new_size;								
				}

				continue;   
			}

			// check if it is a direct branch or a direct call instr:
			if (instr_map[i].orig_targ_addr == 0) {
				continue;  // not a direct branch or a direct call instr.
			}


			// fix instr displacement:			
			new_size = fix_direct_br_call_displacement(i);
			if (new_size < 0)
				return -1;

			if (instr_map[i].size != (unsigned int)new_size) {
			   size_diff += (new_size - instr_map[i].size);
			   instr_map[i].size = (unsigned int)new_size;
			}

		}  // end int i=0; i ..

	} while (size_diff != 0);

   return 0;
 }

int copy_instrs_to_tc()
{
	int cursor = 0;
	// cerr << "NUM_INSTR_MAP: " << num_of_instr_map_entries<<endl;
	for (int i=0; i < num_of_instr_map_entries; i++) {

	  if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
		  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
	      return -1;
	  }	  

	  memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

	  cursor += instr_map[i].size;
	}

	return 0;
}

inline void commit_translated_routines() 
{
	// Commit the translated functions: 
	// Go over the candidate functions and replace the original ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc
	
		if (translated_rtn[i].instr_map_entry >= 0) {
				    
			if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {						

				RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

				//debug print:				
				// if (rtn == RTN_Invalid()) {
				// 	cerr << "committing rtN: Unknown";
				// } else {
				// 	cerr << "committing rtN: " << RTN_Name(rtn);
				// }
				// cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

						
				if (RTN_IsSafeForProbedReplacement(rtn)) {
					RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);
					// AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);							

					// if (origFptr == NULL) {
					// 	cerr << "RTN_ReplaceProbed failed.";
					// } else {
					// 	cerr << "RTN_ReplaceProbed succeeded. ";
					// }
					// cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
					// 		<< " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;	

					dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);												
				}												
			}
		}
	}
}

int allocate_and_init_memory(IMG img) 
{
	// Calculate size of executable sections and allocate required memory:
	//
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			if (rtn == RTN_Invalid())
				continue;

			max_ins_count += RTN_NumIns  (rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.
	// max_ins_count *= 10000;
	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}


	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:		
	char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}
	
	tc = (char *)addr;
	return 0;
}

/* ===================================================================== */
/* Boolean Functions */
/* ===================================================================== */

// Check if current address is caller to function to inline
bool is_addr_to_inline_func(vector<INLINE_FUNCTION_INFO>& inline_functions, INLINE_FUNCTION_INFO& info, ADDRINT address) {
	auto it = find_if(inline_functions.begin(), inline_functions.end(),
					  [&address](const INLINE_FUNCTION_INFO & func) {
						  return func.call_ins_address == address;
					  });
	if (it == inline_functions.end())
		return false;
	info = *it;
		
	if (KnobVerbose) {
		cout << " Inside is_addr_to_inline_func" << endl;
		cout << " Callee rtn address: " << it->callee_rtn_address << "; Call ins address: " << it->call_ins_address << endl;
	}
	
	return true;
}

// Check if address is in range [head, tail]
bool is_addr_in_range(ADDRINT address, ADDRINT head, ADDRINT tail) {
    return address >= head && address <= tail;
}

// Check if address exists in routine BBLs
bool is_addr_in_rtn_bbls(INS ins, ADDRINT rtn_address, vector<BBL_INFO>::iterator bbls_it_begin, vector<BBL_INFO>::iterator bbls_it_end) {
	ADDRINT target_address = INS_DirectControlFlowTargetAddress(ins);

	// Iterate over routine BBLs
	for (auto it = bbls_it_begin; it != bbls_it_end; ++it) { 
		if (is_addr_in_range(target_address, it->head_address, it->tail_address))
			return true;
		if (target_address < it->head_address)
			return false;
	}
	
	return false;
}

/* ===================================================================== */
/* Utility Functions */
/* ===================================================================== */

int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size) {
	// copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

	if (xed_decoded_inst_get_length (xedd) != size) {
		cerr << "Invalid instruction decoding" << endl;
		return -1;
	}

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
	
	xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
	  orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;	
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
	
	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;
	}	
	
	// add a new entry in the instr_map:
	
	instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].targ_map_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;	
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

	num_of_instr_map_entries++;

	// update expected size of tc:
	tc_cursor += new_size;    	     

	if (num_of_instr_map_entries >= max_ins_count) {
		cerr << "out of memory for map_instr" << endl;
		return -1;
	}
	

    // debug print new encoded instr:
	if (KnobVerbose) {
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
	}

	return new_size;
}

void revert_jump(xed_decoded_inst_t *xedd, INS jumpIns) {       
    xed_category_enum_t category_enum = xed_decoded_inst_get_category(xedd);

    if (category_enum != XED_CATEGORY_COND_BR) 
        return;

    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(xedd);

    if (iclass_enum == XED_ICLASS_JRCXZ)
        return;    // do not revert JRCXZ

    xed_iclass_enum_t 	retverted_iclass;

	// Invert jump condition of ins
    switch (iclass_enum) {

        case XED_ICLASS_JB:
            retverted_iclass = XED_ICLASS_JNB;		
            break;

        case XED_ICLASS_JBE:
            retverted_iclass = XED_ICLASS_JNBE;
            break;

        case XED_ICLASS_JL:
            retverted_iclass = XED_ICLASS_JNL;
            break;
    
        case XED_ICLASS_JLE:
            retverted_iclass = XED_ICLASS_JNLE;
            break;

        case XED_ICLASS_JNB: 
            retverted_iclass = XED_ICLASS_JB;
            break;

        case XED_ICLASS_JNBE: 
            retverted_iclass = XED_ICLASS_JBE;
            break;

        case XED_ICLASS_JNL:
        retverted_iclass = XED_ICLASS_JL;
            break;

        case XED_ICLASS_JNLE:
            retverted_iclass = XED_ICLASS_JLE;
            break;

        case XED_ICLASS_JNO:
            retverted_iclass = XED_ICLASS_JO;
            break;

        case XED_ICLASS_JNP: 
            retverted_iclass = XED_ICLASS_JP;
            break;

        case XED_ICLASS_JNS: 
            retverted_iclass = XED_ICLASS_JS;
            break;

        case XED_ICLASS_JNZ:
            retverted_iclass = XED_ICLASS_JZ;
            break;

        case XED_ICLASS_JO:
            retverted_iclass = XED_ICLASS_JNO;
            break;

        case XED_ICLASS_JP: 
            retverted_iclass = XED_ICLASS_JNP;
            break;

        case XED_ICLASS_JS: 
            retverted_iclass = XED_ICLASS_JNS;
            break;

        case XED_ICLASS_JZ:
            retverted_iclass = XED_ICLASS_JNZ;
            break;

        default:
            return;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(xedd);

    // Set the reverted opcode:
    xed_encoder_request_set_iclass(xedd, retverted_iclass);

    xed_uint8_t enc_buf[max_inst_len];
    unsigned int max_size = max_inst_len;
    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode(xedd, enc_buf, max_size, &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        return;
    }
    
    if (KnobVerbose)
    {
        cerr << "Perform jump revert" << endl;
        // Print the original and the new reverted cond instructions:
        //
        cerr << "    orig instr: " << "0x" << hex << INS_Address(jumpIns) << " " << INS_Disassemble(jumpIns) << endl;
    }
    
    xed_decoded_inst_t new_xedd;
    xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&new_xedd, enc_buf, max_inst_len);
    
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << INS_Address(jumpIns) << endl;
        return;
    }

    if (KnobVerbose)
    {
        char buf[2048];
        xed_format_context(XED_SYNTAX_INTEL, &new_xedd, buf, 2048, INS_Address(jumpIns), 0, 0);
        cerr << "    new  instr: " << "0x" << hex << INS_Address(jumpIns) << " " << buf << endl << endl;
    }
    
    *xedd = new_xedd;
}

void add_instruction(INS ins, bool revert=false) {
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;							
	
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

	xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(INS_Address(ins)), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		ADDRINT addr = INS_Address(ins);
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
		return;
	}
	
	// Revert jump
	if (revert)
		revert_jump(&xedd, ins);

	// Add ins to instr_map:
	int rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
	if (rc < 0) {
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
		return;
	}	
}

xed_decoded_inst_t create_unconditional_jump() {
    if (KnobVerbose)
        cout << "Create unconditional jump" << endl;
    
    unsigned char itext[max_inst_len] = { 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00 };

    xed_decoded_inst_t xedd;	
    xed_decoded_inst_zero(&xedd); // ,&dstate 
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
   
    // xed_encoder_request_set_iclass(&xedd, XED_ICLASS_JMP);
    xed_error_enum_t xed_error = xed_decode(&xedd, XED_STATIC_CAST(const xed_uint8_t*,itext), max_inst_len);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
    }
    
    return xedd;
}

void add_jump_ins(EXTRACTED_BBL_INFO &bbl, ADDRINT jump_address) {
	// Create and add unconditional jump to instr_map
	xed_decoded_inst_t xedd = create_unconditional_jump();
	int rc = add_new_instr_entry(&xedd, -1, xed_decoded_inst_get_length(&xedd));
	if (rc < 0) {
        cerr << "ERROR: failed during instructon translation." << endl;
        translated_rtn[translated_rtn_num].instr_map_entry = -1;
        return;
    }

    instr_map[num_of_instr_map_entries - 1].orig_targ_addr = jump_address;
    bbl.inserted_to_map = true;
}

void update_jumps_to_deleted_ins(vector<DELETED_INS>& deleted_ins, int rtn_start_entry, int rtn_end_entry) {
	// Iterate over routine instr_map entries
	for (int i = rtn_start_entry; i < rtn_end_entry; i++) {
		if (instr_map[i].orig_targ_addr) {
			// Check if target address is to deleted ins
			for (const auto& ins : deleted_ins) {
				if (ins.address == instr_map[i].orig_targ_addr)
					instr_map[i].orig_targ_addr = ins.next_address;
			}
		}
	}
}

/* ===================================================================== */
/* BBL Functions */
/* ===================================================================== */

EXTRACTED_BBL_INFO fast_forward_bbl(INS &ins, BBL_INFO &bbl_info, vector<BBL_INFO>::iterator bbls_it_begin, vector<BBL_INFO>::iterator bbls_it_end) {
    if (KnobVerbose)
        cout << "Start fast forward BBL" << endl;
 
    ADDRINT ins_address = INS_Address(ins);
    // Save extracted BBL ins
    vector<INS> ins_vector;
    while (is_addr_in_range(ins_address, bbl_info.head_address, bbl_info.tail_address)) {
		if (ins_address == bbl_info.tail_address && // Current address is tail
			(INS_Category(ins) == XED_CATEGORY_UNCOND_BR || // And is direct jump to target
			INS_Category(ins) == XED_CATEGORY_COND_BR) 
			&& INS_IsDirectControlFlow(ins)) {
				if (!is_addr_in_rtn_bbls(ins, bbl_info.rtn_address, bbls_it_begin, bbls_it_end)) { // Fix: ignore ins with target address not in profiling
					if (KnobVerbose) {
						cout << "Routine: " << RTN_Name(RTN_FindByAddress(bbl_info.rtn_address)) 
							 << " Ignore ins: " << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;				
					}
					break;		
			}		
		}	
		
		ins_vector.push_back(ins);
		
		if (ins_address == bbl_info.tail_address) 
			break;
		ins = INS_Next(ins);
		if (!INS_Valid(ins))
			break;
		ins_address = INS_Address(ins); 
	}
    
    if (KnobVerbose)
        cout << "Finish fast forward BBL" << endl;
	
    return EXTRACTED_BBL_INFO(ins_vector, bbl_info.head_address, bbl_info.tail_address,
							  (INS_IsDirectControlFlow(ins) && INS_IsDirectBranch(ins)) ? INS_DirectControlFlowTargetAddress(ins) : 0,
							  INS_Valid(INS_Next(ins)) ? INS_Address(INS_Next(ins)) : 0,
							  INS_Category(ins) == XED_CATEGORY_COND_BR,
							  bbl_info.jump_count, 
							  INS_IsCall(ins) && INS_IsDirectControlFlow(ins),
							  INS_IsIndirectControlFlow(ins), 
							  !INS_IsControlFlow(ins));
}

/* ===================================================================== */
/* Function Inlining */
/* ===================================================================== */

void function_inline(INLINE_FUNCTION_INFO& info, ADDRINT next_ins_address, list<EXTRACTED_BBL_INFO>& rtn_graph, vector<DELETED_INS>& deleted_ins, int bbl_id) {
	if (KnobVerbose)
		cout << "Callee rtn address: " << hex << info.callee_rtn_address << " BBL id: " << dec << bbl_id << endl; 

	// Advance iterator to insert after caller BBL
	auto it = rtn_graph.begin();
	advance(it, bbl_id);
	
	// Open callee routine
	RTN callee_rtn = RTN_FindByAddress(info.callee_rtn_address); 
	RTN_Open(callee_rtn); 

	// Iterate over instructions
	// Save and insert BBLs
	for (INS ins = RTN_InsHead(callee_rtn); INS_Valid(ins); ins = INS_Next(ins)) {		
		ADDRINT address = INS_Address(ins); // Callee address
		auto bbl_it = find_if(info.rtn_bbls.begin(), info.rtn_bbls.end(),
					  [&address](const BBL_INFO & bbl) {
						  return bbl.head_address == address;
					  });
		if (bbl_it == info.rtn_bbls.end())
			continue;
		
		// Fast forward BBL and add to graph
		EXTRACTED_BBL_INFO extracted_bbl = fast_forward_bbl(ins, *bbl_it, info.rtn_bbls.begin(), info.rtn_bbls.end());
		
		// BBL is empty
		if (!extracted_bbl.instructions.size()) 
			continue;
		
		rtn_graph.insert(it, extracted_bbl);
	}
	
	// Check if last ins is return
	advance(it, -1);
	INS last_ins = it->instructions.back();
	if (INS_IsRet(last_ins)) {
		deleted_ins.push_back(DELETED_INS(INS_Address(last_ins), next_ins_address));
		it->instructions.pop_back(); // Remove "ret"
	}
	
	// Close callee routine
	RTN_Close(callee_rtn); 
}

void create_rtn_graph(RTN rtn, list<EXTRACTED_BBL_INFO>& rtn_graph, map<ADDRINT, TRANSLATED_RTN_INFO>::iterator it, vector<DELETED_INS>& deleted_ins) {		
	// Open routine
	RTN_Open(rtn);
	
	// Iterate over instructions
	// Save and insert BBLs
	vector<INSERT_INLINE_INFO> insert_inline_info;

	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
		ADDRINT rtn_address = RTN_Address(rtn);
		ADDRINT first_address = INS_Address(ins); // Caller address
		
		// Find BBL
		auto bbl_it = find_if(translated_rtn_map[rtn_address].rtn_bbls.begin(), 
					  translated_rtn_map[rtn_address].rtn_bbls.end(),
					  [&first_address](const BBL_INFO & bbl) {
						  return bbl.head_address == first_address;
					  });
		if (bbl_it == translated_rtn_map[rtn_address].rtn_bbls.end())
			continue;
		
		// Fast forward BBL and add to graph
		EXTRACTED_BBL_INFO extracted_bbl = fast_forward_bbl(ins, *bbl_it, translated_rtn_map[rtn_address].rtn_bbls.begin(), translated_rtn_map[rtn_address].rtn_bbls.end());
		
		// BBL is empty
		if (!extracted_bbl.instructions.size()) 
			continue;
		
		rtn_graph.push_back(extracted_bbl);
		
		if (!KnobNoInline) {
			// Routine has calls to inline functions
			if (it->second.has_inline_function && extracted_bbl.instructions.size()) {
				INLINE_FUNCTION_INFO info;
				ADDRINT last_address = INS_Address(extracted_bbl.instructions.back()); // Caller address
				
				// Check if last address is call to inlined function 
				// Fast forward inlined function
				if (is_addr_to_inline_func(it->second.inline_functions, info, last_address)) { 
					// Remove (and save) call ins
					EXTRACTED_BBL_INFO& curr_bbl = rtn_graph.back();
					deleted_ins.push_back(DELETED_INS(last_address, info.callee_rtn_address));
					curr_bbl.instructions.pop_back();
					curr_bbl.tail_direct_call = false;
					curr_bbl.is_regaular_cmd = true;
									
					// Save insert inlined function info
					insert_inline_info.push_back(INSERT_INLINE_INFO(rtn_graph.size(), info, INS_Address(INS_Next(ins))));
				}
			}
		}
	}
	 
	// Close routine
	RTN_Close(rtn);

	if (!KnobNoInline) {
		int bbl_offset = 0; // Updated function insert index
		// Insert inlined functions
		for (auto& func : insert_inline_info) {
			function_inline(func.info, func.address, rtn_graph, deleted_ins, func.bbl_id + bbl_offset);
			bbl_offset =  func.info.rtn_bbls.size();
			
			if (KnobVerbose)
				cout << "BBL offset: " << bbl_offset << endl;
		}
	}

	// Update BBL & FT BBL id
	int i = 1;
	for (auto& bbl : rtn_graph) {
		bbl.bbl_id = i;
		bbl.bbl_ft_id = (i != (int)rtn_graph.size()) ? bbl.bbl_id + 1 : 0;	
		i++;
		
		if (KnobVerbose) {
			cout << dec << "BBL id: " << dec << bbl.bbl_id;
			cout << " FT id: " << dec << bbl.bbl_ft_id << endl;
		}
	}
	
	// Update JUMP BBL id
	for (auto& curr_bbl : rtn_graph) {
		if (&curr_bbl == &rtn_graph.back()) // Last BBL has no jump
			continue;
			
		ADDRINT jump_address = curr_bbl.jump_address;
		auto bbl_it = find_if(rtn_graph.begin(), rtn_graph.end(),
					  [&jump_address](const EXTRACTED_BBL_INFO & bbl) {
						   return is_addr_in_range(jump_address, bbl.head_address, bbl.tail_address);
					  });
		if (bbl_it == rtn_graph.end()) { // Jump out of routine scope
			if (KnobVerbose)
				cout << endl;
			continue;
		}
			
		curr_bbl.bbl_jump_id = bbl_it->bbl_id;
		
		if (KnobVerbose) {
			cout << "BBL id: " << dec << curr_bbl.bbl_id << " ";
			cout << " JUMP id: " << dec << curr_bbl.bbl_jump_id << endl;
		}
		
	}
}

/* ===================================================================== */
/* Code Reordering */
/* ===================================================================== */
int add_hot_bbls(map<int, EXTRACTED_BBL_INFO>& bbls, int bbl_id) {
	if (bbls[bbl_id].inserted_to_map || !bbls[bbl_id].is_hot)
		return -1;
	
	if (KnobVerbose) {
		cout << "========================" << endl;
		cout << "Insert hot block number: " << dec << bbl_id << endl;
		cout << "========================" << endl;
	}
	
	for (const auto& ins : bbls[bbl_id].instructions) { // Add BBL to instr_map
		if (INS_Address(ins) != bbls[bbl_id].tail_address) {
			if (KnobVerbose)
				cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			
			add_instruction(ins);
		} 
		
		else if (bbls[bbl_id].revert_jump) { // Revert last ins
			add_instruction(ins, true);
			if (bbls[bbls[bbl_id].bbl_jump_id].instructions.empty()) // JUMP BBL id is empty: take next BBL jump
				bbls[bbl_id].bbl_jump_id++;
				
			instr_map[num_of_instr_map_entries - 1].orig_targ_addr =  bbls[bbls[bbl_id].bbl_jump_id].head_address; // Update new target address
			
			if (KnobVerbose) 
				cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins)
					 << "New target: 0x" << hex << bbls[bbls[bbl_id].bbl_jump_id].head_address << " to bbl number: " << dec << bbls[bbl_id].bbl_jump_id << endl;		
		} 
		
		else { // Add last ins
			if (KnobVerbose)
				cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			
			add_instruction(ins);
		}
	}
	
	if (bbls[bbls[bbl_id].bbl_ft_id].inserted_to_map) {
		if (KnobVerbose)
			cout << "Add jump BBL: " << bbl_id << " to BBL: " << bbls[bbl_id].bbl_ft_id << endl;
		
		add_jump_ins(bbls[bbl_id], bbls[bbl_id].ft_address);
	} 
	
	else if (bbls[bbl_id].bbl_next_id == (int)bbls.size()) {
		if (KnobVerbose)
			cout << "Add jump BBL: " << bbl_id << " to BBL: " << bbls[(int)bbls.size()].bbl_id << endl;
		
		add_jump_ins(bbls[bbl_id], bbls[(int)bbls.size()].head_address);
	}
	
	bbls[bbl_id].inserted_to_map = true;
	return bbls[bbl_id].bbl_next_id;
}

void add_cold_bbls(map<int, EXTRACTED_BBL_INFO>& bbls, int bbl_id) {
	if (KnobVerbose) {
		cout << "========================" << endl;
		cout << "Insert cold block number: " << dec << bbl_id << endl;
		cout << "========================" << endl;
	}
	
	for (const auto& ins : bbls[bbl_id].instructions) { // Add BBL to instr_map
		if (KnobVerbose)
			cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
		
		add_instruction(ins);
	}
	
	if (bbls[bbl_id].has_conditonal_jump || bbls[bbl_id].tail_direct_call)
		add_jump_ins(bbls[bbl_id], bbls[bbl_id].ft_address);

	bbls[bbl_id].inserted_to_map = true;
}

void reorder_rtn_graph(list<EXTRACTED_BBL_INFO>& rtn_graph, vector<DELETED_INS>& deleted_ins) {
	map<int, EXTRACTED_BBL_INFO> bbls; // KEY: bbl_id
	int rtn_start_entry = num_of_instr_map_entries;
	
	// Save BBLs to map 
	for (const auto& bbl : rtn_graph) 
		bbls[bbl.bbl_id] = bbl;

	// Reorder BBLs
	int i = 1;
	while (1) {
		if (i == (int)bbls.size() || bbls[i].is_hot)
			break;
		
		if (KnobVerbose) { 
			cout << "********************" << endl;
			cout << "Hot BBL: " << dec << i << endl;
		}
		
		int ft_bbl = bbls[i].bbl_ft_id;
		int jump_bbl = bbls[i].bbl_jump_id;
		bbls[i].inserted_to_map = false;
		bbls[i].bbl_next_id = ft_bbl; // Default value 
	
		if (bbls[i].tail_direct_call || bbls[ft_bbl].tail_direct_call)
			bbls[i].bbl_next_id = ft_bbl;
		
		else if (bbls[i].is_regaular_cmd)
			bbls[i].bbl_next_id = i + 1;

		else if(bbls[i].is_indirect_jmp)
			bbls[i].bbl_next_id = ft_bbl;
		
		else if (!bbls[i].has_conditonal_jump && !KnobNoReorder)
			bbls[i].bbl_next_id = jump_bbl;
		
		else if (bbls[ft_bbl].tail_address == bbls[jump_bbl].tail_address) // JUMP is to nested BBL (can't reorder them)
			bbls[i].bbl_next_id = ft_bbl;

		else if (!bbls[i].jump_greater_ft) // FT is hotter than JUMP: don't reorder
			bbls[i].bbl_next_id = ft_bbl;

		else if (jump_bbl == i) // BBL jumps to itself: don't reorder
			bbls[i].bbl_next_id = ft_bbl;

		else if (bbls[ft_bbl].revert_jump) // bbl[i]'s FT is placed before i: don't revert bbl[i]
			bbls[i].bbl_next_id = ft_bbl;

		else if (bbls[ft_bbl].tail_address != bbls[jump_bbl].tail_address  && !KnobNoReorder) { // Reorder - swap JUMP and FT BBLs	
			int new_ft_id = bbls[i].bbl_jump_id;
			ADDRINT new_ft_addr = bbls[i].jump_address;
			bbls[i].bbl_jump_id = bbls[i].bbl_ft_id; 
			bbls[i].bbl_ft_id = new_ft_id; 
			bbls[i].revert_jump = true;
			bbls[i].jump_address = bbls[i].ft_address;
			bbls[i].ft_address = new_ft_addr;
			bbls[i].bbl_next_id = bbls[i].bbl_ft_id;
			
			if (KnobVerbose)
				cout << "Swap JUMP & FT in BBL: " << dec << i << "; New FT: "<< bbls[i].bbl_ft_id << "; New JUMP: " << bbls[i].bbl_jump_id << endl;	
		}

		bbls[i].is_hot = true;
		i = bbls[i].bbl_next_id;
	}

	// Insert reordered BBLs to instr_map
	int next_id = add_hot_bbls(bbls, 1);

	while (next_id != -1)
		next_id = add_hot_bbls(bbls, next_id);

	for (unsigned i = 1; i < bbls.size(); i++) {	
		if (bbls[i].is_hot || bbls[i].inserted_to_map)
			continue;
		
		add_cold_bbls(bbls, i);
	}
	
	// Last bbl
	int last_bbl = (int)bbls.size();
	
	if (KnobVerbose) {
		cout << "========================" << endl;
		cout << "Insert last block: " << dec << last_bbl << endl;
		cout << "========================" << endl;
	}

	for (const auto& ins : bbls[last_bbl].instructions) { // Add BBL to instr_map
			if (KnobVerbose)
				cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			
			add_instruction(ins);
	}
	
	update_jumps_to_deleted_ins(deleted_ins, rtn_start_entry, num_of_instr_map_entries);
}

int find_candidate_rtns_for_translation(IMG img) {
	// Iterate and mark routines for translation
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {	
			if (rtn == RTN_Invalid()) {
			  cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
  			  continue;
			}

			ADDRINT rtn_addr = RTN_Address(rtn);
			vector<DELETED_INS> deleted_ins;

			auto it = translated_rtn_map.find(rtn_addr);
			if (it == translated_rtn_map.end())
				continue;
			
			if ((int)it->second.rtn_bbls.size() < max((int)KnobBbl, 2)) 
				continue;
					
			translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);			
			translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
			translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
			translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;	
			
			if (KnobCC1Enable) {
				set<string> cc1_rtns = {"find_reg_note", "ggc_set_mark", "rtx_equal_p", "reg_scan_mark_refs", "gcc_mark_rtx_children_1", "build_function_type",
										"layout_type", "convert_to_ssa", "coalesce_if_unconflicting", "schedule_insns", "sched_analyze_2"};
				if (cc1_rtns.find(RTN_Name(rtn)) == cc1_rtns.end())
					continue;
			}	

			if (KnobVerbose) {
				cout << "================================" << endl;
				cout << "Routine name: "<< RTN_Name(rtn) << endl;
				cout << "================================" << endl;
			}
			
			// Create routine graph
			list<EXTRACTED_BBL_INFO> rtn_graph;
			create_rtn_graph(rtn, rtn_graph, it, deleted_ins);
			
			// Reorder routine graph 
			reorder_rtn_graph(rtn_graph, deleted_ins);		

			translated_rtn_num++;
		 } 
	} 

	return 0;
}

/* ===================================================================== */
/* Parse file */
/* ===================================================================== */

int parse_file(string csv_filename) {	
    ifstream file(csv_filename, ios::in);
    
    string line, word;
    int line_index = 0, col_index = 1;
    
	// Read lines from file
    while (getline(file, line)) {
        stringstream ss(line);
        col_index = 1;
		
		// Line columns
        ADDRINT caller_rtn_address = 0, inline_rtn_addr = 0, caller_ins_address = 0;
		
        int num_callers_to_routine = 0, num_ret_ins = 0, direct_jumps_out = 0,
			indirect_branches = 0, num_caller_calls = 0,
			bad_rbp_rsp_offset = 0, ret_is_last_inst = 0, direct_jump_to_callee = 0, 
			call_to_middle_of_rtn = 0;
        
        string rtn_name = ""; 
		
		vector<BBL_INFO> rtn_bbls;
		
		// Function to inline info
        ADDRINT head_address = 0, tail_address = 0;
		int jump_greater_ft;

		// Skip headers
		if (line_index == 0) {
            line_index++;
            continue;
        }

		// Read columns in line
        while (getline(ss, word, ',')) {
			// Callee & Caller
            if (col_index == CSV_RTN_ADDR)
                inline_rtn_addr = static_cast<ADDRINT>(stoul(word, nullptr, 16));

            else if (col_index == CSV_RTN_NAME) 
                rtn_name = word;

            else if (col_index == CSV_NUM_CALLERS_TO_ROUTINE) 
                num_callers_to_routine = stoi(word);

            else if (col_index == CSV_NUM_CALLER_CALLS)
                num_caller_calls = stoi(word);

            else if (col_index == CSV_NUM_RETS_INS) 
                num_ret_ins = stoi(word);

            else if (col_index == CSV_DIRECT_JUMPS_OUT) 
                direct_jumps_out = stoi(word);

            else if (col_index == CSV_INDIRECT_BRANCHES) 
                indirect_branches = stoi(word);

            else if (word.find('.') != string::npos) {
                col_index++;
                continue;
            }
            else if (col_index == CSV_CALLER_INS_ADDRESS) 
                caller_ins_address = static_cast<ADDRINT>(stoi(word));
			
            else if (col_index == CSV_CALLER_RTN_ADDR)
                caller_rtn_address = static_cast<ADDRINT>(stoi(word));

            else if (col_index == CSV_BAD_RBP_RSP_OFFSET)
                bad_rbp_rsp_offset = stoi(word);

            else if (col_index == CSV_RET_IS_LAST_INST)
                ret_is_last_inst = stoi(word);

            else if (col_index == CSV_DIRECT_JUMP_TO_CALLEE)
                direct_jump_to_callee = stoi(word);

            else if (col_index == CSV_CALL_TO_MIDDLE_OF_RTN)
                call_to_middle_of_rtn = stoi(word);
	    	
			// BBLs
            else if (col_index >= CSV_BBLS) {
                if (head_address == 0)
                    head_address = static_cast<ADDRINT>(stoul(word, nullptr, 16));
                else if (tail_address == 0)
                    tail_address = static_cast<ADDRINT>(stoul(word, nullptr, 16));
                else {
                    jump_greater_ft = stoi(word);
					// Save BBL info
					BBL_INFO bbl_info;
					bbl_info.head_address = head_address;
					bbl_info.tail_address = tail_address;
					bbl_info.jump_count = jump_greater_ft; // 1 - Jump count is greater than FT count, 0 - Otherwise
					bbl_info.rtn_address = inline_rtn_addr;
					// Add BBL to routine info
					rtn_bbls.push_back(bbl_info);
					
                    head_address = 0;
                    tail_address = 0;
                }
            }
			
            col_index++;
        }

		// Function to inline
        if (caller_rtn_address != inline_rtn_addr && // Check for recursion
			num_callers_to_routine == 1 &&
            num_caller_calls >= KnobCall &&
            num_ret_ins == 1 &&
            !direct_jumps_out && 
            !indirect_branches &&
            !bad_rbp_rsp_offset &&
            ret_is_last_inst == 1 &&
            !direct_jump_to_callee &&
            !call_to_middle_of_rtn) {
                if (KnobVerbose)
					cout << "Inline function: " << rtn_name << endl;

                inline_routines_vec.push_back(inline_rtn_addr);
				
                auto it = translated_rtn_map.find(caller_rtn_address);
                if (it != translated_rtn_map.end()) { // Caller Routine exists in map - add call ins to an inline function
					INLINE_FUNCTION_INFO info(inline_rtn_addr, caller_ins_address, rtn_bbls);
                    it->second.add_inline_function(info, false);
                } 
                else { // Caller Routine doesn't exist in map
                    TRANSLATED_RTN_INFO rtn_info(inline_rtn_addr, caller_ins_address, true, false, rtn_bbls);
                    translated_rtn_map[caller_rtn_address] = rtn_info;
                }

            }
			
		// Hot Routine 
        else {
			if (KnobVerbose)
				cout << "Hot routine: " << rtn_name <<endl;
			 
			auto it = translated_rtn_map.find(inline_rtn_addr);
			if (it == translated_rtn_map.end()) { // Add hot routine
				TRANSLATED_RTN_INFO rtn_info(0, 0, false, false, rtn_bbls);
				translated_rtn_map[inline_rtn_addr] = rtn_info;
			}
			
			else // Routine exists - add BBLs
				translated_rtn_map[inline_rtn_addr].rtn_bbls = rtn_bbls;
		}
        line_index++;
    }

    // Update functions that are both callee and caller
    for (auto it = translated_rtn_map.begin(); it != translated_rtn_map.end(); ++it) { 
        auto inline_it = find(inline_routines_vec.begin(), inline_routines_vec.end(), it->first);
        if (inline_it != inline_routines_vec.end())
            it->second.is_inline_function = true;
    }
	
    if (KnobVerbose) {
		cout << "==========================================" << endl;
		for (auto it = translated_rtn_map.begin(); it != translated_rtn_map.end(); ++it) { 
			int i = 0;
			cout << "----------------------------" << endl;
			cout << "Caller address " <<it->first << endl;
			for (const INLINE_FUNCTION_INFO &obj : it->second.inline_functions) {
				cout << "Callee address: " << hex << obj.callee_rtn_address << "; Caller ins address: " << hex << obj.call_ins_address << " " << i << endl;
				i++;
			}
		}
		cout << "==========================================" << endl;
	}
	
    file.close();
    return 0;
}

/* ============================================ */
/* Main translation routine                     */
/* ============================================ */

void ImageLoad(IMG img, void *v) {
	// debug print of all images' instructions
	//dump_all_image_instrs(img);

    // Step 0: Check the image and the CPU:
	if (!IMG_IsMainExecutable(img))
		return;
	int rc = 0;

	// Parse CSV
	rc = parse_file(KnobFile.Value().c_str());
	if (rc < 0)
		return;

	// Step 1: Check size of executable sections and allocate required memory:	
	rc = allocate_and_init_memory(img);
	if (rc < 0)
		return;

	cout << "after memory allocation" << endl;

	
	// Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
	rc = find_candidate_rtns_for_translation(img);
	if (rc < 0)
		return;

	cout << "after identifying candidate routines" << endl;	 
	
	// Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
	rc = chain_all_direct_br_and_call_target_entries();
	if (rc < 0 )
		return;
	
	cout << "after calculate direct br targets" << endl;

	// Step 4: fix rip-based, direct branch and direct call displacements:
	rc = fix_instructions_displacements();
	if (rc < 0 )
		return;
	
	cout << "after fix instructions displacements" << endl;


	// Step 5: write translated routines to new tc:
	rc = copy_instrs_to_tc();
	if (rc < 0 )
		return;

	cout << "after write all new instructions to memory tc" << endl;

   if (KnobDumpTranslatedCode) {
	   cout << "Translation Cache dump:" << endl;
       dump_tc();  // dump the entire tc

	   cout << endl << "instructions map dump:" << endl;
	   dump_entire_instr_map();     // dump all translated instructions in map_instr
   }


	// Step 6: Commit the translated routines:
	//Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
	  commit_translated_routines();	
	//   cout << "after commit translated routines" << endl;
    }
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {   
    PIN_InitSymbols();
    if(PIN_Init(argc,argv))
        return Usage();

    if (KnobProf) { // PROF
    	TRACE_AddInstrumentFunction(Trace, 0);        
        RTN_AddInstrumentFunction(Routine, 0);
        PIN_AddFiniFunction(Fini, 0);
    }
	
    else if (KnobOpt) { // OPT
		IMG_AddInstrumentFunction(ImageLoad, 0);
		PIN_StartProgramProbed();
	}
 
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

