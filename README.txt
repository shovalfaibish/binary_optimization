a. Names:
	Shoval Faibish
	Or Barnea

b. Compilation command: 
	make PIN_ROOT=<pindir> obj-intel64/project.so (under project.cpp directory)

c. How to run the tool:
	PROF mode: <pindir>/pin -t obj-intel64/project.so -prof -<file_to_run>
	OPT mode: <pindir>/pin -t obj-intel64/project.so -inst -<file_to_run>

d. Format of the profile file:
	CALLEE: rtn address
	CALLEE: rtn name
	CALLER: # callers to rtn
	CALLER: # callers' calls
	CALLEE: # return ins
	CALLEE: # direct jumps out 
	CALLEE: # indirect branches
	CALLER: ins address
	CALLER: rtn address
	CALLEE: bad rsp/rbp offset 
	CALLEE: ret is last inst 
	CALLER: direct jump to callee 
	CALLEE: call to middle of rtn 
	* For each CALLEE BBL: 
		CALLEE: BBL: head address
		CALLEE: BBL: tail address
		CALLEE: BBL: T > NT

e. Candidate inline functions criteria:
	CALLEE: rtn address != CALLER: rtn address (to avoid recursion)
	CALLER: # callers to rtn == 1
	CALLER: # callers' calls >= KnobCall
	CALLEE: # return ins == 1
	CALLEE: # direct jumps out == false
	CALLEE: # indirect branches == false
	CALLEE: bad rsp/rbp offset == false 
	CALLEE: ret is last inst == true
	CALLER: direct jump to callee == false
	CALLEE: call to middle of rtn == false

f. For every routine that is reordered, we distinguish a BBL as "hot" if it is taken more times in a conditional branch.

*** To optimize cc1, use the flag -cc1_enable (otherwise it won't work)