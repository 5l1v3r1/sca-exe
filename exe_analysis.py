import pefile
import lief
from capstone import *
import rzpipe
from qiling import *
import platform
import os



syst = platform.uname()[0]
if syst == "Linux":
    os.system("clear")
else:
    os.system("cls")


#colors
Yellow = "\033[0;33m"
Green = "\033[0;32m"
White = "\033[0;37m"



#banner
print(Yellow+"""


                                                     
  _____  _____   ___  ___ __ _ _ __  _ __   ___ _ __ 
 / _ \ \/ / _ \ / __|/ __/ _` | '_ \| '_ \ / _ \ '__|
|  __/>  <  __/ \__ \ (_| (_| | | | | | | |  __/ |   
 \___/_/\_\___| |___/\___\__,_|_| |_|_| |_|\___|_|   
                                                     
github : https://github.com/rm-onata


""")





exe_file = input("enter exe file to analysis : "+White)



pefile_exe = pefile.PE(exe_file)
print(pefile_exe)





print("\n\n\n")
input(Green+"press enter to continuation"+White)
print("\n\n\n")



lief_exe = lief.parse(exe_file)
print(lief_exei)



print("\n\n\n")
input(Green+"press enter to continuation"+White)
print("\n\n\n")



capstone_exe = pefile.PE(exe_file)
entry_point = capstone_exe.OPTIONAL_HEADER.AddressOfEntryPoint
data = capstone_exe.get_memory_mapped_image()[entry_point:]
cs = Cs(CS_ARCH_X86, CS_MODE_32)
rdbin = cs.disasm(data, 0x1000)

for i in rdbin:
	print("0x%x:\t%s\t%s" %(i.adderss, i.mnemonic, i.op_str))




print("\n\n\n")
input(Green+"press enter to continuation"+White)
print("\n\n\n")



rzpipe_exe = rzpipe.open(exe_file)
rzpipe_exe.cmd('aa')

print(rzpipe_exe.cmd("afl"))
print(rzpipe_exe.cmdj("aflj"))
print(rzpipe_exe.cmdj("ij").core.format)

rzpipe_exe.quit()



print("\n\n\n")
input(Green+"press enter to continuation"+White)
print("\n\n\n")


ql = Qiling([exe_file], rootfs="dll\\examples\\rootfs\\x8664_windows")
ql.run()


#END
