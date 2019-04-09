package main

import "fmt"

func (mix *Mix) printPools() {

	fmt.Printf("\n----------\nmix.FirstPool:\n")
	for i := range mix.FirstPool {

		k, _ := mix.FirstPool[i].PubKeyOrAddr()

		if mix.IsExit {
			fmt.Printf("\t%d = '%s'\n", i, k)
		} else {
			fmt.Printf("\t%d = '%x'\n", i, k)
		}
	}
	fmt.Printf("len(mix.FirstPool): %d, cap(mix.FirstPool): %d\n\n", len(mix.FirstPool), cap(mix.FirstPool))

	fmt.Printf("mix.SecPool:\n")
	for i := range mix.SecPool {

		k, _ := mix.SecPool[i].PubKeyOrAddr()

		if mix.IsExit {
			fmt.Printf("\t%d = '%s'\n", i, k)
		} else {
			fmt.Printf("\t%d = '%x'\n", i, k)
		}
	}
	fmt.Printf("len(mix.SecPool): %d, cap(mix.SecPool): %d\n\n", len(mix.SecPool), cap(mix.SecPool))

	fmt.Printf("mix.ThirdPool:\n")
	for i := range mix.ThirdPool {

		k, _ := mix.ThirdPool[i].PubKeyOrAddr()

		if mix.IsExit {
			fmt.Printf("\t%d = '%s'\n", i, k)
		} else {
			fmt.Printf("\t%d = '%x'\n", i, k)
		}
	}
	fmt.Printf("len(mix.ThirdPool): %d, cap(mix.ThirdPool): %d\n\n", len(mix.ThirdPool), cap(mix.ThirdPool))

	fmt.Printf("mix.NextPool:\n")
	for i := range mix.NextPool {

		k, _ := mix.NextPool[i].PubKeyOrAddr()

		if mix.IsExit {
			fmt.Printf("\t%d = '%s'\n", i, k)
		} else {
			fmt.Printf("\t%d = '%x'\n", i, k)
		}
	}
	fmt.Printf("len(mix.NextPool): %d, cap(mix.NextPool): %d\n\n", len(mix.NextPool), cap(mix.NextPool))

	fmt.Printf("mix.OutPool:\n")
	for i := range mix.OutPool {

		k, _ := mix.OutPool[i].PubKeyOrAddr()

		if mix.IsExit {
			fmt.Printf("\t%d = '%s'\n", i, k)
		} else {
			fmt.Printf("\t%d = '%x'\n", i, k)
		}
	}
	fmt.Printf("len(mix.OutPool): %d, cap(mix.OutPool): %d\n----------\n\n", len(mix.OutPool), cap(mix.OutPool))
}
