package releaseupdate
import("os";"path/filepath";"strings";"testing")
func write(t *testing.T,dir,v string){t.Helper();p:=filepath.Join(dir,"VOLVE_Centro_Proteccion_"+strings.ReplaceAll(v,".","_")+".exe");if e:=os.WriteFile(p,[]byte("MZ"),0600);e!=nil{t.Fatal(e)}}
func TestDowngrade(t *testing.T){d:=t.TempDir();write(t,d,"0.27.5");write(t,d,"0.28.5");v,e:=HighestInstalledPanel(d);if e!=nil||v!="0.28.5"{t.Fatalf("%q %v",v,e)};if EnsureNoInstalledDowngrade(d,"0.28.4")==nil{t.Fatal("downgrade accepted")};if e:=EnsureNoInstalledDowngrade(d,"0.28.6");e!=nil{t.Fatal(e)}}
func TestInvalidTarget(t *testing.T){d:=t.TempDir();if e:=os.Mkdir(filepath.Join(d,"VOLVE_Centro_Proteccion_0_99_0.exe"),0700);e!=nil{t.Fatal(e)};if _,e:=HighestInstalledPanel(d);e==nil{t.Fatal("directory accepted")}}
func TestNoInstall(t *testing.T){d:=t.TempDir();if e:=EnsureNoInstalledDowngrade(d,"0.28.5");e!=nil{t.Fatal(e)}}
