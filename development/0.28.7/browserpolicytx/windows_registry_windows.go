//go:build windows

package browserpolicytx

// A disposable Windows Registry backend ONLY for a private HKCU lab hive.
// The map is deliberately incapable of reaching Chrome/Edge/Firefox policies.
// It is NOT a production writer or a security-boundary implementation.
import (
    "context"
    "encoding/binary"
    "errors"
    "fmt"
    "os"
    "regexp"
    "strings"
    "syscall"
    "unsafe"
)

var numberOnly=regexp.MustCompile(`^[0-9]{1,18}$`)
var advapi=syscall.NewLazyDLL("advapi32.dll")
var procCreate=advapi.NewProc("RegCreateKeyExW")
var procSet=advapi.NewProc("RegSetValueExW")
var procDeleteValue=advapi.NewProc("RegDeleteValueW")
var procDeleteTree=advapi.NewProc("RegDeleteTreeW")

type WindowsRegistryLab struct {root string;closed bool}

func NewWindowsRegistryLab()(*WindowsRegistryLab,error){
    run,attempt:=os.Getenv("GITHUB_RUN_ID"),os.Getenv("GITHUB_RUN_ATTEMPT")
    if os.Getenv("GITHUB_ACTIONS")!="true" ||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
        !numberOnly.MatchString(run)||!numberOnly.MatchString(attempt){
        return nil,errors.New("native Registry lab only permitted on hosted disposable Windows CI")
    }
    root:=`SOFTWARE\VOLVE-CI-BrowserPolicies-`+run+"-"+attempt
    ptr,err:=syscall.UTF16PtrFromString(root)
    if err!=nil{return nil,err}
    var existing syscall.Handle
    err=syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER,ptr,0,syscall.KEY_READ|syscall.KEY_WOW64_64KEY,&existing)
    if err==nil {
        syscall.RegCloseKey(existing)
        return nil,errors.New("existing CI lab hive refused")
    }
    if !errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)&&!errors.Is(err,syscall.ERROR_PATH_NOT_FOUND){
        return nil,fmt.Errorf("cannot prove lab hive absence: %w",err)
    }
    key,err:=createLabKey(root)
    if err!=nil{return nil,err}
    syscall.RegCloseKey(key)
    return &WindowsRegistryLab{root:root},nil
}
func createLabKey(key string)(syscall.Handle,error){
    ptr,err:=syscall.UTF16PtrFromString(key);if err!=nil{return 0,err}
    var result syscall.Handle
    rights:=uintptr(syscall.KEY_READ|syscall.KEY_SET_VALUE|syscall.KEY_WOW64_64KEY)
    rc,_,_:=procCreate.Call(uintptr(syscall.HKEY_CURRENT_USER),uintptr(unsafe.Pointer(ptr)),0,0,0,
        rights,0,uintptr(unsafe.Pointer(&result)),0)
    if rc!=0{return 0,syscall.Errno(rc)}
    return result,nil
}
func labSuffix(v Value)(string,error){
    switch v.Key {
    case chrome+`\URLBlocklist`:return `\chrome\block`,nil
    case edge+`\URLBlocklist`:return `\edge\block`,nil
    case firefox+`\WebsiteFilter\Block`:return `\firefox\block`,nil
    case chrome:return `\chrome\main`,nil
    case edge:return `\edge\main`,nil
    case firefox+`\DNSOverHTTPS`:return `\firefox\doh`,nil
    default:return "",errors.New("unexpected policy namespace")
    }
}
func(s *WindowsRegistryLab) path(v Value)(string,error){
    if s==nil||s.closed{return "",errors.New("lab hive unavailable")}
    if v.Hive!="HKEY_LOCAL_MACHINE" {return "",errors.New("unexpected policy hive")}
    suffix,err:=labSuffix(v);if err!=nil{return "",err}
    if v.Name==""||strings.ContainsAny(v.Name,`/\:`){return "",errors.New("unsafe value name")}
    return s.root+suffix,nil
}
func openLabKey(path string)(syscall.Handle,error){
    ptr,err:=syscall.UTF16PtrFromString(path);if err!=nil{return 0,err}
    var result syscall.Handle
    err=syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER,ptr,0,
        syscall.KEY_QUERY_VALUE|syscall.KEY_SET_VALUE|syscall.KEY_WOW64_64KEY,&result)
    return result,err
}
func readLabValue(h syscall.Handle,name string)(uint32,[]byte,bool,error){
    ptr,err:=syscall.UTF16PtrFromString(name);if err!=nil{return 0,nil,false,err}
    var kind,size uint32
    err=syscall.RegQueryValueEx(h,ptr,nil,&kind,nil,&size)
    if errors.Is(err,syscall.ERROR_FILE_NOT_FOUND){return 0,nil,false,nil}
    if err!=nil&&!errors.Is(err,syscall.ERROR_MORE_DATA){return 0,nil,false,err}
    if size==0||size>1<<14{return 0,nil,false,errors.New("unbounded Registry value")}
    value:=make([]byte,size)
    err=syscall.RegQueryValueEx(h,ptr,nil,&kind,&value[0],&size)
    if err!=nil{return 0,nil,false,err}
    return kind,value[:size],true,nil
}
func encodeValue(v Value)(uint32,[]byte,error){
    switch v.Type {
    case "REG_SZ":
        if v.DWord!=nil||v.Value==""{return 0,nil,errors.New("invalid REG_SZ")}
        units,err:=syscall.UTF16FromString(v.Value);if err!=nil{return 0,nil,err}
        raw:=make([]byte,2*len(units))
        for i,n:=range units{binary.LittleEndian.PutUint16(raw[2*i:],n)}
        return syscall.REG_SZ,raw,nil
    case "REG_DWORD":
        if v.DWord==nil||v.Value!=""{return 0,nil,errors.New("invalid REG_DWORD")}
        raw:=make([]byte,4)
        binary.LittleEndian.PutUint32(raw,*v.DWord)
        return syscall.REG_DWORD,raw,nil
    default:return 0,nil,errors.New("unknown registry type")
    }
}
func(s *WindowsRegistryLab) Exists(ctx context.Context,v Value)(bool,error){
    if err:=ctx.Err();err!=nil{return false,err}
    path,err:=s.path(v);if err!=nil{return false,err}
    key,err:=openLabKey(path)
    if errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)||errors.Is(err,syscall.ERROR_PATH_NOT_FOUND){return false,nil}
    if err!=nil{return false,err}
    defer syscall.RegCloseKey(key)
    _,_,found,err:=readLabValue(key,v.Name)
    return found,err
}
func(s *WindowsRegistryLab) CreateOnly(ctx context.Context,v Value)error{
    if err:=ctx.Err();err!=nil{return err}
    path,err:=s.path(v);if err!=nil{return err}
    kind,raw,err:=encodeValue(v);if err!=nil{return err}
    key,err:=createLabKey(path);if err!=nil{return err}
    defer syscall.RegCloseKey(key)
    _,_,present,err:=readLabValue(key,v.Name)
    if err!=nil{return err}
    if present{return errors.New("existing value cannot be overwritten")}
    // Lab-only: no cross-process transaction lease. Never use as a product
    // writer where the read/set window would otherwise be a TOCTOU hazard.
    ptr,err:=syscall.UTF16PtrFromString(v.Name);if err!=nil{return err}
    rc,_,_:=procSet.Call(uintptr(key),uintptr(unsafe.Pointer(ptr)),0,uintptr(kind),
        uintptr(unsafe.Pointer(&raw[0])),uintptr(len(raw)))
    if rc!=0{return syscall.Errno(rc)}
    return nil
}
func(s *WindowsRegistryLab) DeleteOnlyIfEqual(ctx context.Context,v Value)error{
    if err:=ctx.Err();err!=nil{return err}
    path,err:=s.path(v);if err!=nil{return err}
    key,err:=openLabKey(path);if err!=nil{return err}
    defer syscall.RegCloseKey(key)
    oldKind,oldRaw,present,err:=readLabValue(key,v.Name)
    if err!=nil{return err}
    expectedKind,expectedRaw,err:=encodeValue(v);if err!=nil{return err}
    if !present||oldKind!=expectedKind||len(oldRaw)!=len(expectedRaw){
        return errors.New("policy value absent or changed; refuse delete")
    }
    for i:=range oldRaw {if oldRaw[i]!=expectedRaw[i]{return errors.New("policy value changed; refuse delete")}}
    ptr,err:=syscall.UTF16PtrFromString(v.Name);if err!=nil{return err}
    rc,_,_:=procDeleteValue.Call(uintptr(key),uintptr(unsafe.Pointer(ptr)))
    if rc!=0{return syscall.Errno(rc)}
    return nil
}
// Cleanup ONLY removes the run-specific HKCU Software/VOLVE-CI test tree.
// No browser-policy paths, machine hives, tasks or DNS adapters are touched.
func(s *WindowsRegistryLab) Cleanup()error{
    if s==nil||s.closed{return nil}
    s.closed=true
    ptr,err:=syscall.UTF16PtrFromString(s.root);if err!=nil{return err}
    rc,_,_:=procDeleteTree.Call(uintptr(syscall.HKEY_CURRENT_USER),uintptr(unsafe.Pointer(ptr)))
    if rc!=0{return syscall.Errno(rc)}
    return nil
}
