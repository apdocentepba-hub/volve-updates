package motorupdate

// The signed publisher activation admission is RECHECKED through the DNS
// transaction. An expired/replaced/replayed permit must never allow another
// netsh write or a final commit. Emergency RESTORE is deliberately NOT
// gated on a live activation permit: otherwise expiry during a failed install
// could strand Windows DNS pointing at a stopped localhost motor.
//
// The production caller must load PublisherKey from its immutable signed
// binary and obtain the nonce, journal/motor/watchdog pins independently from
// sealed OS evidence. This private wrapper DOES NOT supply those OS attestations
// and is not an installer or a replacement for the independent SYSTEM watchdog.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "time"
)

type DNSActivationPublisherAuthorization struct {
 GrantJSON []byte
 Signature []byte
 PinnedPublisherKey ed25519.PublicKey
 PinnedEvidence DNSActivationExternallyPinnedEvidence
}

// Snapshot once before a controller starts using the evidence. A caller
// must not concurrently mutate inputs during this initial copy. Subsequent
// changes to caller-owned buffers cannot change an admitted transaction.
func snapshotDNSActivationAuthorization(auth DNSActivationPublisherAuthorization) DNSActivationPublisherAuthorization {
 auth.GrantJSON=append([]byte(nil),auth.GrantJSON...)
 auth.Signature=append([]byte(nil),auth.Signature...)
 auth.PinnedPublisherKey=append(ed25519.PublicKey(nil),auth.PinnedPublisherKey...)
 return auth
}

type publisherScopedDNSActivationGuard struct {
 inner DNSActivationSafetyGuard
 rawGrant []byte
 signature []byte
 publisherKey ed25519.PublicKey
 pinned DNSActivationExternallyPinnedEvidence
 originalJournal []byte
 independentDNSJournalSHA256 string
 now func()time.Time
}

func newPublisherScopedDNSActivationGuard(
 ctx context.Context, rawOriginalJournal []byte, independentlyPinnedSHA256 string,
 permit DNSActivationPublisherAuthorization, inner DNSActivationSafetyGuard,
 now func()time.Time,
)(DNSActivationSafetyGuard,error){
 if ctx==nil||inner==nil||now==nil{return nil,errors.New("signed DNS admission missing context, guarded recovery or clock")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if permit.PinnedEvidence.OriginalDNSJournalSHA256!=independentlyPinnedSHA256{
  return nil,errors.New("signed activation original DNS pin differs from protected transaction")
 }
 guard:=&publisherScopedDNSActivationGuard{
  inner:inner,
  rawGrant:append([]byte(nil),permit.GrantJSON...),
  signature:append([]byte(nil),permit.Signature...),
  publisherKey:append(ed25519.PublicKey(nil),permit.PinnedPublisherKey...),
  pinned:permit.PinnedEvidence,
  originalJournal:append([]byte(nil),rawOriginalJournal...),
  independentDNSJournalSHA256:independentlyPinnedSHA256,
  now:now,
 }
 if err:=guard.verifyPublisherAdmission(ctx,independentlyPinnedSHA256);err!=nil{return nil,err}
 return guard,nil
}

func(g *publisherScopedDNSActivationGuard)verifyPublisherAdmission(ctx context.Context,pin string)error{
 if g==nil||g.inner==nil||ctx==nil{return errors.New("signed DNS activation guard not initialized")}
 if err:=ctx.Err();err!=nil{return err}
 if pin!=g.independentDNSJournalSHA256 || pin!=g.pinned.OriginalDNSJournalSHA256 {
  return errors.New("active DNS journal no longer matches publisher signed transaction")
 }
 if _,err:=VerifyPublisherSignedDNSActivationGrant(
  ctx,g.rawGrant,g.signature,g.publisherKey,g.pinned,g.now(),
 );err!=nil{
  return fmt.Errorf("publisher authorization for DNS activation denied: %w",err)
 }
 if _,err:=VerifyDNSOriginalJournal(ctx,g.originalJournal,pin);err!=nil{
  return fmt.Errorf("publisher-bound original DNS changed during activation: %w",err)
 }
 return nil
}
func(g *publisherScopedDNSActivationGuard)VerifyArmed(ctx context.Context,pin string)error{
 if err:=g.verifyPublisherAdmission(ctx,pin);err!=nil{return err}
 if err:=g.inner.VerifyArmed(ctx,pin);err!=nil{return err}
 // OS attestation can take long enough to exhaust a short-lived permit.
 // Never authorize the next operation on evidence that expired inside it.
 return g.verifyPublisherAdmission(ctx,pin)
}
func(g *publisherScopedDNSActivationGuard)VerifyLiveProtection(ctx context.Context,pin string)error{
 if err:=g.verifyPublisherAdmission(ctx,pin);err!=nil{return err}
 if err:=g.inner.VerifyLiveProtection(ctx,pin);err!=nil{return err}
 return g.verifyPublisherAdmission(ctx,pin)
}
func(g *publisherScopedDNSActivationGuard)CommitActive(ctx context.Context,pin string)error{
 if err:=g.verifyPublisherAdmission(ctx,pin);err!=nil{return err}
 return g.inner.CommitActive(ctx,pin)
}
func(g *publisherScopedDNSActivationGuard)RecoverIndependently(ctx context.Context,pin string)error{
 // Do not require activation authorization here. After partial failure the
 // signed grant might be expired; the SYSTEM watchdog has its own distinct
 // publisher-bound recovery permit and protected journal to authenticate.
 if g==nil||g.inner==nil{return errors.New("independent recovery guard absent")}
 return g.inner.RecoverIndependently(ctx,pin)
}
