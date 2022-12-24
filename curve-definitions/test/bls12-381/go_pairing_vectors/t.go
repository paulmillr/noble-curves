package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	kilic "github.com/kilic/bls12-381"
)

func main() {
	g1 := kilic.NewG1()
	g2 := kilic.NewG2()
	gt := kilic.NewGT()
	p1 := g1.One()
	p2 := g2.One()
	bls := kilic.NewEngine()
	out := []string{}
	for i := 0; i < 1000; i++ {
		res := bls.AddPair(p1, p2).Result()
		out = append(out, hex.EncodeToString(gt.ToBytes(res)))
		g1.Add(p1, p1, g1.One())
		g2.Add(p2, p2, g2.One())

	}
	bytes, _ := json.Marshal(out)
	fmt.Println(string(bytes))

}
