package spfgate

import (
	"fmt"
	"math/rand"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type SPFG struct {
	Fakename	string
	Pointer		uintptr
	Fakeid		uint16
	Realid 		uint16
}


func (f *SPFG)Recover(){
	var sysid uint16
	sysid = f.Realid
	windows.WriteProcessMemory(0xffffffffffffffff,f.Pointer+4,(*byte)(unsafe.Pointer(&sysid)),2,nil)
}


func strin(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	if index < len(str_array) && str_array[index] == target {
		return true
	}
	return false
}

func SpfGate(sysid uint16,none []string) (*SPFG,error){
	newfcg := new(SPFG)
	apilen := len(apiconst)
	newfcg.Fakeid = sysid

	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s) // initialize local pseudorandom generator
	i := 0

	for{
		i++
		idx := r.Intn(len(apiconst))
		for strin(apiconst[idx],none){
			idx = r.Intn(len(apiconst))
		}
		nt,e := syscall.LoadLibrary(string([]byte{'n','t','d','l','l','.','d','l','l'}))
		if e != nil{
			return nil,fmt.Errorf("load dll err")
		}
		tmpApi,e := syscall.GetProcAddress(nt,apiconst[idx])
		if e != nil{
			if i >= apilen{
				return nil,fmt.Errorf("load dll err")
			}
			continue
		}
		
		if tmpApi == 0{
			continue
		}
		if *(*byte)(unsafe.Pointer(tmpApi)) == 0x4c &&
			*(*byte)(unsafe.Pointer(tmpApi+1)) == 0x8b &&
			*(*byte)(unsafe.Pointer(tmpApi+2)) == 0xd1 &&
			*(*byte)(unsafe.Pointer(tmpApi+3)) == 0xb8 &&
			*(*byte)(unsafe.Pointer(tmpApi+6)) == 0x00 &&
			*(*byte)(unsafe.Pointer(tmpApi+7)) == 0x00 {
			newfcg.Realid = uint16(*(*byte)(unsafe.Pointer(tmpApi+4))) | uint16(*(*byte)(unsafe.Pointer(tmpApi+5)))<<8
			windows.WriteProcessMemory(0xffffffffffffffff,tmpApi+4,(*byte)(unsafe.Pointer(&sysid)),2,nil)
			newfcg.Pointer = tmpApi
			newfcg.Fakename = apiconst[idx]
			return newfcg,nil
		}
		if i >= apilen{
			break
		}
	}
	return newfcg,fmt.Errorf("tmpApi found Err")
}
