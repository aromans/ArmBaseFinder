#Ghidra Plugin 

func_manager = currentProgram.getFunctionManager()

with open('./func_offsets.txt', 'w') as f:
	for function in func_manager.getFunctions(True):
		func_name = function.getName()
		start_address = function.getEntryPoint().toString()
	
		f.write(start_address + ',')
