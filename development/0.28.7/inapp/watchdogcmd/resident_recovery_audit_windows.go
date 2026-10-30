//go:build windows

package main

// Read-only evidence gate for a future production watchdog. This file never
// schedules, starts, imports or changes a task, executable, DNS or adapter.
// The live motor switch remains hard-blocked elsewhere.
import (
    "bytes"
    "context"
    "encoding/xml"
    "io"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "unicode/utf16"
    "unicode/utf8"

    "volve-browser-protection/motorupdate"
)

const residentRecoveryParent = "legacy-engine-recovery"
const residentRecoveryFolder = "original-before-upgrade"
const residentRecoveryExe = "VOLVE_DNS_Legacy_Recovery.exe"
const residentRecoveryTask = "VOLVE_DNS_Legacy_Task.xml"
const residentRecoveryReceipt = "VOLVE_DNS_Legacy_Recovery.json"
const residentLegacyExe = "VOLVE_DNS_Server_0270.exe"

type residentTaskXML struct {
    XMLName xml.Name `xml:"Task"`
    Principals []struct {
        Principal []struct { UserID string `xml:"UserId"` } `xml:"Principal"`
    } `xml:"Principals"`
    Actions []struct {
        InnerXML string `xml:",innerxml"`
        Exec []struct {
            Command string `xml:"Command"`
            Arguments string `xml:"Arguments"`
        } `xml:"Exec"`
    } `xml:"Actions"`
}

// Task Scheduler commonly exports XML declared as UTF-16 even when the
// PowerShell wrapper serializes its returned string as UTF-8. Accept both
// canonical UTF-16 BOM bytes and valid UTF-8 text with that declaration,
// WITHOUT changing the original bytes whose SHA-256 was already checked.
func normalizeResidentXML(data []byte)([]byte,error) {
    if len(data)<100 || len(data)>maxXML {
        return nil,errors.New("resident XML outside bounded size")
    }
    var s string
    if len(data)>=2 && ((data[0]==0xff && data[1]==0xfe) || (data[0]==0xfe && data[1]==0xff)) {
        if (len(data)-2)%2!=0{return nil,errors.New("truncated resident UTF-16 XML")}
        little:=data[0]==0xff
        units:=make([]uint16,(len(data)-2)/2)
        for i:=range units {
            a,b:=data[2+i*2],data[3+i*2]
            if little {units[i]=uint16(a)|uint16(b)<<8} else {units[i]=uint16(b)|uint16(a)<<8}
        }
        s=string(utf16.Decode(units))
        if strings.ContainsRune(s,'\uFFFD'){return nil,errors.New("malformed resident UTF-16 XML")}
    }else{
        if !utf8.Valid(data) || bytes.IndexByte(data,0)>=0 {
            return nil,errors.New("resident XML is not valid UTF-8 or BOM-marked UTF-16")
        }
        s=string(data)
        s=strings.TrimPrefix(s,"\uFEFF")
    }
    if strings.HasPrefix(s,"<?xml") {
        end:=strings.Index(s,"?>")
        if end<0 || end>200{return nil,errors.New("resident XML declaration invalid")}
        upper:=strings.ToUpper(s[:end])
        for _,encoding:=range []string{"UTF-16LE","UTF-16BE","UTF-16"} {
            i:=strings.Index(upper,encoding)
            if i>=0 {
                s=s[:i]+"UTF-8"+s[i+len(encoding):]
                break
            }
        }
    }
    if len(s)>maxXML {return nil,errors.New("normalized resident XML oversized")}
    return []byte(s),nil
}

func validateResidentTaskXML(data []byte, expectedExe string) error {
    if len(data)<100 || len(data)>maxXML || !filepath.IsAbs(expectedExe) {
        return errors.New("resident SYSTEM XML or executable path invalid")
    }
    normalized,err:=normalizeResidentXML(data)
    if err!=nil{return err}
    var task residentTaskXML
    if err:=xml.Unmarshal(normalized,&task);err!=nil{return fmt.Errorf("resident task XML invalid: %w",err)}
    if task.XMLName.Local!="Task" || len(task.Principals)!=1 ||
       len(task.Principals[0].Principal)!=1 || len(task.Actions)!=1 ||
       len(task.Actions[0].Exec)!=1 {
        return errors.New("resident task must have exactly one SYSTEM principal and one Exec action")
    }
    if err:=exactOneResidentAction(task.Actions[0].InnerXML);err!=nil{return err}
    owner:=strings.TrimSpace(task.Principals[0].Principal[0].UserID)
    action:=task.Actions[0].Exec[0]
    if owner!="SYSTEM" && owner!="S-1-5-18" {
        return errors.New("recovery XML does not describe SYSTEM principal")
    }
    if !strings.EqualFold(filepath.Clean(action.Command),filepath.Clean(expectedExe)) ||
        action.Arguments!="--dns-service" {
        return errors.New("recovery task XML points to another motor or arguments")
    }
    return nil
}

// XML unmarshalling ignores unfamiliar action types by default. Verify all
// direct action nodes independently so a ComHandler or other task action
// cannot hide alongside the one expected DNS Exec.
func exactOneResidentAction(inner string) error {
    decoder:=xml.NewDecoder(bytes.NewReader([]byte(inner)))
    depth:=0
    count:=0
    for {
        token,err:=decoder.Token()
        if err==io.EOF {break}
        if err!=nil{return fmt.Errorf("resident task actions XML invalid: %w",err)}
        switch node:=token.(type) {
        case xml.StartElement:
            if depth==0 {
                count++
                if node.Name.Local!="Exec" {
                    return errors.New("resident task contains an unrecognized extra action")
                }
            }
            depth++
        case xml.EndElement:
            depth--
            if depth<0 {return errors.New("resident task actions nesting invalid")}
        }
    }
    if depth!=0 || count!=1 {return errors.New("resident task must contain exactly one Exec action")}
    return nil
}

// verifyResidentRecoveryACL verifies ownership AND all ACEs, not only whether
// the directory says it is inherited. A user who owns an otherwise restrictive
// DACL could rewrite it and forge a rollback. A single untrusted ACE or owner
// makes the entire bundle ineligible. Never repairs an existing ACL.
func verifyResidentRecoveryACL(ctx context.Context, dir string) error {
    if err:=ctx.Err();err!=nil{return err}
    if !filepath.IsAbs(dir) || filepath.Base(dir)!=residentRecoveryFolder ||
       filepath.Base(filepath.Dir(dir))!=residentRecoveryParent {
        return errors.New("rollback is outside the expected resident recovery tree")
    }
    parent:=filepath.Dir(dir)
    expected:=[]string{residentRecoveryExe,residentRecoveryTask,residentRecoveryReceipt}
    entries,err:=os.ReadDir(dir);if err!=nil{return err}
    if len(entries)!=len(expected){return errors.New("unexpected files in resident rollback")}
    seen:=map[string]bool{}
    for _,entry:=range entries {
        if entry.IsDir(){return errors.New("nested resident rollback directory forbidden")}
        seen[entry.Name()]=true
    }
    for _,name:=range expected {
        if !seen[name] {return fmt.Errorf("resident rollback file missing: %s",name)}
    }
    paths:=[]string{parent,dir}
    for _,name:=range expected {paths=append(paths,filepath.Join(dir,name))}
    quoted:=make([]string,0,len(paths))
    for _,p:=range paths {
        stat,err:=os.Lstat(p);if err!=nil{return err}
        if stat.Mode()&os.ModeSymlink!=0 {return errors.New("resident rollback contains a link")}
        if (p==parent || p==dir) && !stat.IsDir(){return errors.New("resident backup parent not a directory")}
        if p!=parent && p!=dir && !stat.Mode().IsRegular(){return errors.New("resident backup data not regular")}
        quoted=append(quoted,q(p))
    }
    // Stable SID checks work even on non-English Windows installations.
    // No writable / delete / change-permissions access for any other SID.
    // Reject even a read-only foreign allow rule to keep the trust policy
    // identical to the exact admin/SYSTEM snapshot policy.
    script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
        "$paths=@("+strings.Join(quoted,",")+");"+
        "$allowed=@('S-1-5-18','S-1-5-32-544');"+
        "foreach($p in $paths){"+
        "$attr=[IO.File]::GetAttributes($p);"+
        "if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse point in resident recovery'};"+
        "if([IO.Directory]::Exists($p)){$acl=[IO.Directory]::GetAccessControl($p)}else{$acl=[IO.File]::GetAccessControl($p)};"+
        "$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;"+
        "if($owner -notin $allowed){throw ('Untrusted owner: '+$owner)};"+
        "if($p -eq $paths[0] -or $p -eq $paths[1]){if(-not $acl.AreAccessRulesProtected){throw 'Recovery tree inherits DACL'}};"+
        "$rights=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]);"+
        "foreach($ace in $rights){"+
        "if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny){throw 'Deny ACE in recovery'};"+
        "if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $ace.IdentityReference.Value -notin $allowed){throw ('Untrusted recovery ACE: '+$ace.IdentityReference.Value)}"+
        "};"+
        "foreach($sid in $allowed){"+
        "if(@($rights|Where-Object{$_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $_.IdentityReference.Value -eq $sid}).Count -eq 0){throw ('Missing recovery trustee: '+$sid)}"+
        "}"+
        "};Write-Output 'RESIDENT_RECOVERY_ACL_OK'"
    out,err:=ps(ctx,script)
    if err!=nil{return fmt.Errorf("resident recovery ACL rejected: %w",err)}
    if out!="RESIDENT_RECOVERY_ACL_OK"{
        return fmt.Errorf("ambiguous resident recovery ACL verification: %q",out)
    }
    return nil
}

type residentRecoveryAudit struct {
    LegacySHA256 string
    TaskXMLSHA256 string
}

// auditResidentRollback checks the recovery bundle independently of the
// installed app, using the exact backup format already written by 0.28.7.
// It does not treat a local backup as a publisher-signed migration permit.
func auditResidentRollback(ctx context.Context,root string)(residentRecoveryAudit,error) {
    var empty residentRecoveryAudit
    if err:=ctx.Err();err!=nil{return empty,err}
    if !filepath.IsAbs(root){return empty,errors.New("installed root must be absolute")}
    base,err:=os.Lstat(root)
    if err!=nil{return empty,err}
    if !base.IsDir() || base.Mode()&os.ModeSymlink!=0 {
        return empty,errors.New("installed root is redirected or not a directory")
    }
    backupDir:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder)
    acl:=func(dir string)error{return verifyResidentRecoveryACL(ctx,dir)}
    record,err:=motorupdate.VerifyUnversionedLegacyRecovery(backupDir,acl)
    if err!=nil{return empty,fmt.Errorf("resident recovery bytes/ACL not trusted: %w",err)}
    xmlPath:=filepath.Join(backupDir,residentRecoveryTask)
    xmlBytes,err:=os.ReadFile(xmlPath);if err!=nil{return empty,err}
    if err:=validateResidentTaskXML(xmlBytes,filepath.Join(root,residentLegacyExe));err!=nil{
        return empty,err
    }
    // Repeat the hash/ACL check after reading the XML to detect replacements
    // during the audit. This is evidence only; a production restore will need
    // open handles and rechecks across its own switch boundary.
    again,err:=motorupdate.VerifyUnversionedLegacyRecovery(backupDir,acl)
    if err!=nil || again!=record {
        return empty,errors.New("resident rollback changed during audit")
    }
    return residentRecoveryAudit{record.ExeSHA256,record.XMLSHA256},nil
}
