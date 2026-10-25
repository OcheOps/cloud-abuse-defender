package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "os"

 "github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

func main() {
 hourly := flag.Float64("hourly-rate",25,"estimated unauthorized spend per hour in USD")
 horizon := flag.Float64("hours",24,"forecast horizon in hours")
 threshold := flag.Float64("threshold",100,"forecast USD threshold")
 confidence := flag.Float64("confidence",90,"threat confidence between 0 and 100")
 minimum := flag.Float64("min-confidence",85,"minimum confidence for recommendation")
 allow := flag.Bool("allow-containment",false,"enable containment recommendation (never executes)")
 flag.Parse()
 decision,err:=policy.Evaluate(policy.Input{HourlyCostUSD:*hourly,HorizonHours:*horizon,ThresholdUSD:*threshold,ThreatConfidence:*confidence,MinConfidence:*minimum,AllowContainment:*allow})
 if err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(2) }
 encoder:=json.NewEncoder(os.Stdout)
 encoder.SetIndent("","  ")
 if err:=encoder.Encode(decision);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
