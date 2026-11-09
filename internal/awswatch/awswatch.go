// Package awswatch is a read-only AWS CLI CloudTrail LookupEvents adapter.
// LookupEvents covers management events, not Bedrock inference/token telemetry.
package awswatch

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os/exec"
 "time"
)

const MaxResponseBytes = 32 << 20

// Runner can be injected for offline tests.
type Runner func(context.Context, ...string) ([]byte, error)

// CLI calls the AWS CLI without a shell or AWS write APIs.
func CLI(ctx context.Context, args ...string) ([]byte, error) {
 out, err := exec.CommandContext(ctx,"aws",args...).Output()
 if err != nil { return nil, fmt.Errorf("AWS CLI failed: %w",err) }
 if len(out) > MaxResponseBytes { return nil, errors.New("AWS CLI output too large") }
 return out,nil
}

type lookupEvent struct {
 EventID string `json:"EventId"`
 CloudTrailEvent string `json:"CloudTrailEvent"`
}

// Fetch converts AWS LookupEvents output into the existing CloudTrail S3 envelope.
// The AWS CLI auto-paginates by default. Any unconsumed NextToken fails closed.
func Fetch(ctx context.Context, run Runner, region string, start,end time.Time) ([]byte,int,error) {
 if run==nil || region=="" || start.IsZero() || end.IsZero() || !end.After(start) || end.After(time.Now().Add(5*time.Minute)) {
  return nil,0,errors.New("invalid runner, region or time range")
 }
 raw,err:=run(ctx,"cloudtrail","lookup-events","--region",region,
  "--start-time",start.UTC().Format(time.RFC3339),
  "--end-time",end.UTC().Format(time.RFC3339),"--output","json")
 if err!=nil{return nil,0,err}
 if len(raw)>MaxResponseBytes{return nil,0,errors.New("CloudTrail response too large")}
 var response struct {
  Events []lookupEvent `json:"Events"`
  NextToken string `json:"NextToken"`
 }
 d:=json.NewDecoder(bytes.NewReader(raw))
 if err:=d.Decode(&response);err!=nil{return nil,0,fmt.Errorf("decode LookupEvents: %w",err)}
 var extra any
 if d.Decode(&extra)!=io.EOF{return nil,0,errors.New("trailing data in LookupEvents response")}
 if response.NextToken!="" {return nil,0,errors.New("incomplete pagination (NextToken present)")}
 seen:=map[string]bool{}
 records:=make([]json.RawMessage,0,len(response.Events))
 for _,ev:=range response.Events {
  if ev.EventID=="" {return nil,0,errors.New("LookupEvents item missing EventId")}
  if seen[ev.EventID]{continue}
  seen[ev.EventID]=true
  var rawEvent map[string]json.RawMessage
  if err:=json.Unmarshal([]byte(ev.CloudTrailEvent),&rawEvent);err!=nil||rawEvent==nil {
   return nil,0,fmt.Errorf("invalid CloudTrail event %q",ev.EventID)
  }
  var id string
  if err:=json.Unmarshal(rawEvent["eventID"],&id);err!=nil||id!=ev.EventID {
   return nil,0,fmt.Errorf("mismatched embedded event ID %q",ev.EventID)
  }
  records=append(records,json.RawMessage(ev.CloudTrailEvent))
 }
 payload,err:=json.Marshal(struct{Records []json.RawMessage `json:"Records"`}{records})
 if err!=nil{return nil,0,err}
 return payload,len(records),nil
}
