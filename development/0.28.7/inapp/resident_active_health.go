package motorupdate

import (
 "context"
 "errors"
)

// ResidentActiveHealthChecks runs ACTUAL UDP DNS and direct TCP network
// probes, while requiring a separately supplied OS-specific identity checker.
// Do not pass a fake identity callback in production. No Windows driver calls
// this constructor yet; real SYSTEM task/EXE identity and publisher permit
// must be verified by a future privileged adapter before finalizing.
type ResidentActiveHealthChecks struct {
 VerifyIdentity func(context.Context,ResidentRecoveryIntent,string) error
 IPv4DNS string
 IPv6DNS string
 TCPAddresses []string
}

func (c ResidentActiveHealthChecks) VerifyRunningIdentity(ctx context.Context,
 intent ResidentRecoveryIntent,outcome string) error {
 if c.VerifyIdentity==nil {return errors.New("missing trusted Windows SYSTEM identity verifier")}
 return c.VerifyIdentity(ctx,intent,outcome)
}
func (c ResidentActiveHealthChecks) ProbeLocalDNS(ctx context.Context) error {
 return ProbeResidentDNSLoopbacks(ctx,c.IPv4DNS,c.IPv6DNS)
}
func (c ResidentActiveHealthChecks) ProbeConnectivity(ctx context.Context) error {
 return ProbeResidentInternetAt(ctx,c.TCPAddresses)
}

// Production network endpoints are never provided by untrusted journal JSON.
// This deliberately does NOT supply the crucial Windows identity checker:
// the OS driver must implement it after independent recovery is armed.
func NewResidentNetworkHealth(identity func(context.Context,ResidentRecoveryIntent,string)error) ResidentActiveHealthChecks {
 return ResidentActiveHealthChecks{
  VerifyIdentity:identity,
  IPv4DNS:"127.0.0.1:53",IPv6DNS:"[::1]:53",
  TCPAddresses:[]string{"1.1.1.1:443","9.9.9.9:443"},
 }
}
