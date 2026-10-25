package policy

import (
 "math"
 "testing"
)

func TestEvaluate(t *testing.T) {
 tests := []struct{
  name string
  input Input
  want Action
  eligible bool
 }{
  {"default alerts", Input{HourlyCostUSD:25,HorizonHours:24,ThresholdUSD:100,ThreatConfidence:90,MinConfidence:85}, Alert,false},
  {"high confidence with opt in",Input{HourlyCostUSD:25,HorizonHours:24,ThresholdUSD:100,ThreatConfidence:90,MinConfidence:85,AllowContainment:true},RecommendContainment,true},
  {"low confidence",Input{HourlyCostUSD:25,HorizonHours:24,ThresholdUSD:100,ThreatConfidence:70,MinConfidence:85,AllowContainment:true},Alert,false},
  {"low spend",Input{HourlyCostUSD:1,HorizonHours:24,ThresholdUSD:100,ThreatConfidence:99,MinConfidence:85,AllowContainment:true},Alert,false},
  {"threshold boundary",Input{HourlyCostUSD:5,HorizonHours:20,ThresholdUSD:100,ThreatConfidence:85,MinConfidence:85,AllowContainment:true},RecommendContainment,true},
 }
 for _,tt:=range tests { t.Run(tt.name,func(t *testing.T){
  got,err:=Evaluate(tt.input)
  if err!=nil {t.Fatal(err)}
  if got.Action!=tt.want || got.EligibleForContainment!=tt.eligible {t.Fatalf("got %+v",got)}
 }) }
}

func TestRejectInvalid(t *testing.T) {
 for _,in := range []Input{
  {HourlyCostUSD:-1}, {HourlyCostUSD:math.NaN()}, {HourlyCostUSD:math.Inf(1)},
  {HorizonHours:-1}, {ThreatConfidence:101}, {ThreatConfidence:math.NaN()},
  {MinConfidence:-1}, {ThresholdUSD:-1},
  {HourlyCostUSD:math.MaxFloat64,HorizonHours:2},
 } {
  if _,err:=Evaluate(in);err==nil {t.Fatalf("accepted invalid input: %+v",in)}
 }
}
