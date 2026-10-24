package vendordb

import "os"

func osRead() ([]byte, error) { return os.ReadFile("vendordb.json") }
