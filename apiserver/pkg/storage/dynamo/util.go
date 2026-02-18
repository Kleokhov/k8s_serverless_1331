package dynamo

import (
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const maxRV = uint64(math.MaxInt64)

func parseRV(item map[string]ddbtypes.AttributeValue, name string) (uint64, error) {
	rv, err := parseUintAttr(item, name)
	if err != nil {
		return 0, err
	}
	if rv == 0 {
		return 0, fmt.Errorf("%s must be > 0", name)
	}
	if rv > maxRV {
		return 0, fmt.Errorf("%s overflow: %d > MaxInt64", name, rv)
	}
	return rv, nil
}

func rvToInt64(rv uint64) (int64, error) {
	if rv > maxRV {
		return 0, fmt.Errorf("rv overflow: %d > MaxInt64", rv)
	}
	return int64(rv), nil
}

func parseUintAttr(item map[string]ddbtypes.AttributeValue, name string) (uint64, error) {
	v, ok := item[name]
	if !ok {
		return 0, fmt.Errorf("missing attribute %q", name)
	}
	n, ok := v.(*ddbtypes.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("attribute %q not a number", name)
	}
	return strconv.ParseUint(n.Value, 10, 64)
}

func parseBinaryAttr(item map[string]ddbtypes.AttributeValue, name string) ([]byte, error) {
	v, ok := item[name]
	if !ok {
		return nil, fmt.Errorf("missing attribute %q", name)
	}
	b, ok := v.(*ddbtypes.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("attribute %q not binary", name)
	}
	return b.Value, nil
}

func parseStringAttr(item map[string]ddbtypes.AttributeValue, attr string) (string, error) {
	av, ok := item[attr]
	if !ok || av == nil {
		return "", fmt.Errorf("missing attribute %q", attr)
	}
	s, ok := av.(*ddbtypes.AttributeValueMemberS)
	if !ok {
		return "", fmt.Errorf("attribute %q: expected String (S), got %T", attr, av)
	}
	if s.Value == "" {
		// Up to you: if empty strings are valid for some attrs, remove this check.
		return "", fmt.Errorf("attribute %q: empty string", attr)
	}
	return s.Value, nil
}

func txnCanceledConditionalFailed(err error, idx int) bool {
	var tce *ddbtypes.TransactionCanceledException
	if !errors.As(err, &tce) {
		return false
	}
	if idx < 0 || idx >= len(tce.CancellationReasons) {
		return false
	}
	code := aws.ToString(tce.CancellationReasons[idx].Code)
	return code == "ConditionalCheckFailed"
}

func isKeyExistsTxnError(err error) bool {
	// We expect 2 operations; Put is index 1.
	return txnCanceledConditionalFailed(err, 1)
}

func isMetaConflictTxnError(err error) bool {
	// Update meta is index 0.
	return txnCanceledConditionalFailed(err, 0)
}
