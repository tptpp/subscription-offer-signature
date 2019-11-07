package main

import "testing"

func TestSignAndVerify(t *testing.T) {
	params := SignParams{
		AppBundleID :"com.example.yourapp",
		ProductIdentifier  :"com.example.yoursubscription",
		OfferID       :"your_offer_id",
		ApplicationUsername :"8E3DC5F16E13537ADB45FB0F980ACDB6B55839870DBCE7E346E1826F5B0296CA",
	}

	result, err := Sign(&params)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	t.Logf("sign ok, params[%+v], result[%+v]", params, result)

	if !Verify(&params, &result) {
		t.Fatalf("verify failed: %v", err)
	}

	sig := []byte(result.Signature)
	sig[0] ^= 0x01
	result.Signature = string(sig)
	if Verify(&params, &result) {
		t.Fatalf("verify should fail, but succedded")
	}
}
