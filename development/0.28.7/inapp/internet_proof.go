package motorupdate

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "net"
    "strings"
    "time"
)

// VerifyInternetTLS confirms that the *Windows configured resolver* can
// resolve an allowed Internet host and establish a certificate-verified TLS
// connection. A raw IP/TCP probe is insufficient: broken DNS could still pass.
// This is a production probe primitive, not a proof that every site is usable.
func VerifyInternetTLS(ctx context.Context) error {
    endpoints:=[]string{"github.com","www.cloudflare.com"}
    errs:=make([]error,0,len(endpoints))
    // Keep the entire check bounded: no network operation can block the
    // independent rollback while waiting for an unreachable remote server.
    probeCtx,cancel:=context.WithTimeout(ctx,12*time.Second)
    defer cancel()
    for _,host:=range endpoints {
        if err:=probeTLSHost(probeCtx,host,net.JoinHostPort(host,"443"),nil);err==nil {
            return nil
        } else {
            errs=append(errs,fmt.Errorf("%s: %w",host,err))
        }
        if probeCtx.Err()!=nil {break}
    }
    return fmt.Errorf("DNS/HTTPS externo no confirmado: %w",errors.Join(errs...))
}

// probeTLSHost is isolated for deterministic local TLS integration tests.
// The production path uses system roots, the expected DNS hostname, port 443,
// and a direct dial through the machine's configured resolver; no proxy and no
// custom resolver to bypass the protected Windows adapter are involved.
func probeTLSHost(ctx context.Context, host, address string, roots *tls.Config) error {
    if host=="" || strings.ContainsAny(host,"/\\:\r\n\t ") {
        return errors.New("destino TLS inválido")
    }
    if address=="" {return errors.New("dirección TCP ausente")}
    dialer:=&net.Dialer{Timeout:5*time.Second,KeepAlive:-1}
    conn,err:=dialer.DialContext(ctx,"tcp",address)
    if err!=nil{return fmt.Errorf("falló la conexión TCP o resolución DNS: %w",err)}
    defer conn.Close()
    conf:=&tls.Config{MinVersion:tls.VersionTLS12,ServerName:host}
    if roots!=nil{
        conf.RootCAs=roots.RootCAs
    }
    client:=tls.Client(conn,conf)
    defer client.Close()
    if deadline,ok:=ctx.Deadline();ok {
        _=client.SetDeadline(deadline)
    }else{
        _=client.SetDeadline(time.Now().Add(5*time.Second))
    }
    if err:=client.HandshakeContext(ctx);err!=nil {
        return fmt.Errorf("TLS o certificado del servidor no válido: %w",err)
    }
    return nil
}
