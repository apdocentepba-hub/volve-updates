package motorupdate

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "net"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

func TestProbeTLSHostAcceptsPinnedLocalCAAndValidHostname(t *testing.T) {
    srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusNoContent)}))
    defer srv.Close()
    cert:=srv.Certificate()
    roots:=x509.NewCertPool()
    roots.AddCert(cert)
    host:="example.com"
    if len(cert.DNSNames)>0{host=cert.DNSNames[0]}
    address:=srv.Listener.Addr().String()
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    if err:=probeTLSHost(ctx,host,address,&tls.Config{RootCAs:roots});err!=nil{t.Fatalf("valid TLS endpoint rejected: %v",err)}
}

func TestProbeTLSHostRejectsUntrustedCertificate(t *testing.T){
    srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusNoContent)}))
    defer srv.Close()
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    err:=probeTLSHost(ctx,"example.com",srv.Listener.Addr().String(),nil)
    if err==nil {t.Fatal("untrusted TLS certificate was accepted")}
}

func TestProbeTLSHostRejectsWrongHostname(t *testing.T){
    srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusNoContent)}))
    defer srv.Close()
    roots:=x509.NewCertPool()
    roots.AddCert(srv.Certificate())
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    if err:=probeTLSHost(ctx,"unrelated.invalid",srv.Listener.Addr().String(),&tls.Config{RootCAs:roots});err==nil {
        t.Fatal("mismatching DNS name was accepted")
    }
}
func TestProbeTLSHostRejectsCancellationAndUnsafeNames(t *testing.T) {
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if err:=probeTLSHost(ctx,"github.com",net.JoinHostPort("127.0.0.1","443"),nil);err==nil{
        t.Fatal("cancelled network probe succeeded")
    }
    for _,host:=range []string{"","example.org:443","https://example.org","example.org\nOther: header"}{
        if err:=probeTLSHost(context.Background(),host,"127.0.0.1:443",nil);err==nil{
            t.Fatalf("invalid probe hostname allowed: %q",host)
        }else if !strings.Contains(err.Error(),"inválido"){
            t.Fatalf("unexpected unsafe-host result: %v",err)
        }
    }
}
