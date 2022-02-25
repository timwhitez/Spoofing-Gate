# Spoofing-Gate
(Hellsgate|Halosgate|Tartarosgate)+Spoofing-Gate. Ensures that all systemcalls go through ntdll.dll


- get sysid from "X"gate

- use Spoofing-Gate to get the Spoofing funtion pointer

- call the pointer

- Recover

```
//get sysid from "X"gate
alloc,e := gabh.MemHgate(str2sha1("NtAllocateVirtualMemory"),str2sha1)
	if e != nil {
		panic(e)
	}
  
var tmplist []string
tmplist = append(tmplist,[]string{"NtAllocateVirtualMemory"}...)


//use Spoofing-Gate to get the Spoofing funtion pointer
alloctmp,e := spfgate.SpfGate(alloc,tmplist)
if e != nil{
  panic(e)
}
tmplist = append(tmplist,alloctmp.Fakename)
fmt.Printf("NtAllocateVirtualMemory|(fake)")
fmt.Printf(alloctmp.Fakename)
fmt.Printf(": 0x%x\n",alloctmp.Pointer)

//call the pointer
r1, _,_ := syscall.Syscall6(
		alloctmp.Pointer, //ntallocatevirtualmemory
		6,
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r1 != 0{
		fmt.Printf("1 %x\n", r1)
		return
	}
	
	
//Recover
alloctmp.Recover()


```


