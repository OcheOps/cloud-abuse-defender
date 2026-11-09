package awswatch

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"
 "time"
)

func TestFetch(t *testing.T) {
 now:=time.Now().UTC().Truncate(time.Second)
 ev:=`{"eventID":"evt-1","eventTime":"2026-11-09T10:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"RunInstances"}`
 body,_:=json.Marshal(map[string]any{"Events":[]any{
  map[string]any{"EventId":"evt-1","CloudTrailEvent":ev},
  map[string]any{"EventId":"evt-1","CloudTrailEvent":ev},
 }})
 mock:=func(_ context.Context,args ...string)([]byte,error){
  if args[0]!="cloudtrail"||args[1]!="lookup-events"{t.Errorf("unexpected AWS args: %v",args)}
  return body,nil
 }
 output,n,err:=Fetch(context.Background(),mock,"us-east-1",now.Add(-time.Minute),now)
 if err!=nil||n!=1||!strings.Contains(string(output),`"Records"`){t.Fatalf("output %q, count %d, err %v",output,n,err)}
}

func TestFetchRejectsBadResponses(t *testing.T) {
 now:=time.Now()
 invalid:=[]string{
  `{"Events":[],"NextToken":"more"}`,
  `{"Events":[{"EventId":"evt-1","CloudTrailEvent":"not-json"}]}`,
  `{"Events":[{"EventId":"evt-1","CloudTrailEvent":"{\\"eventID\\":\\"wrong\\"}"}]}`,
  `{"Events":[]} trailing`,
 }
 for _,body:=range invalid {
  _,_,err:=Fetch(context.Background(),func(context.Context,...string)([]byte,error){return []byte(body),nil},"us-east-1",now.Add(-time.Minute),now)
  if err==nil{t.Fatalf("accepted invalid payload %s",body)}
 }
 _,_,err:=Fetch(context.Background(),func(context.Context,...string)([]byte,error){return nil,errors.New("AWS unavailable")},"us-east-1",now.Add(-time.Minute),now)
 if err==nil {t.Fatal("expected runner failure")}
}
