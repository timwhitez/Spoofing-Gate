# Spoofing-Gate
(Hellsgate|Halosgate|Tartarosgate)+Spoofing-Gate. Ensures that all systemcalls go through ntdll.dll


- get sysid from "X"gate

- use Spoofing-Gate to get the Spoofing funtion pointer

- call the pointer


```
alloc,e := gabh.MemHgate(str2sha1("NtAllocateVirtualMemory"),str2sha1)
	if e != nil {
		panic(e)
	}
  
  
var tmplist []string
tmplist = append(tmplist,[]string{"NtAllocateVirtualMemory"}...)


alloctmp,e := spfgate.SpfGate(alloc,tmplist)
if e != nil{
  panic(e)
}
tmplist = append(tmplist,alloctmp.Fakename)
fmt.Printf("NtAllocateVirtualMemory|(fake)")
fmt.Printf(alloctmp.Fakename)
fmt.Printf(": 0x%x\n",alloctmp.Pointer)



```


