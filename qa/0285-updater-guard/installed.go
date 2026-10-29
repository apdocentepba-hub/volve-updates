package releaseupdate

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "strings"
)

func CompareVersions(a,b string)(int,error){
 re:=regexp.MustCompile(`^\d+\.\d+\.\d+$`)
 if !re.MatchString(a)||!re.MatchString(b){return 0,errors.New("invalid version")}
 var av,bv [3]uint64
 if _,e:=fmt.Sscanf(a,"%d.%d.%d",&av[0],&av[1],&av[2]);e!=nil{return 0,e}
 if _,e:=fmt.Sscanf(b,"%d.%d.%d",&bv[0],&bv[1],&bv[2]);e!=nil{return 0,e}
 for i:=0;i<3;i++ {if av[i]<bv[i]{return -1,nil};if av[i]>bv[i]{return 1,nil}}
 return 0,nil
}

// Same installation guard as VOLVE 0.28.5, copied into standalone CI harness.
func HighestInstalledPanel(dir string)(string,error){
 if !filepath.IsAbs(dir){return "",errors.New("directorio de instalación no absoluto")}
 items,err:=os.ReadDir(dir)
 if errors.Is(err,os.ErrNotExist){return "",nil}
 if err!=nil{return "",err}
 pattern:=regexp.MustCompile(`^VOLVE_Centro_Proteccion_([0-9]+)_([0-9]+)_([0-9]+)\.exe$`)
 maxVersion:=""
 for _,item:=range items{
  m:=pattern.FindStringSubmatch(item.Name())
  if m==nil{continue}
  if !item.Type().IsRegular(){return "",fmt.Errorf("panel instalado no es archivo regular: %q",item.Name())}
  info,e:=item.Info();if e!=nil{return "",e}
  if info.Size()<2{return "",fmt.Errorf("panel instalado vacío: %q",item.Name())}
  v:=strings.Join(m[1:],".")
  if _,e=CompareVersions(v,"0.0.0");e!=nil{return "",fmt.Errorf("versión instalada inválida %q: %w",v,e)}
  if maxVersion==""{maxVersion=v;continue}
  cmp,e:=CompareVersions(maxVersion,v);if e!=nil{return "",e}
  if cmp<0{maxVersion=v}
 }
 return maxVersion,nil
}
func EnsureNoInstalledDowngrade(dir,candidate string)error{
 newest,err:=HighestInstalledPanel(dir);if err!=nil{return err}
 if newest==""{return nil}
 cmp,err:=CompareVersions(candidate,newest);if err!=nil{return err}
 if cmp<0{return fmt.Errorf("versión %s rechazada: ya existe un panel %s más reciente",candidate,newest)}
 return nil
}
