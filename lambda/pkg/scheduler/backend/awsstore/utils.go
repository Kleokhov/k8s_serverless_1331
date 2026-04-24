package awsstore

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

var (
	ErrQueueEmpty    = errors.New("queue is empty")
	ErrQueueNotFound = errors.New("queue item not found")
)

func priorityOf(pInfo *framework.QueuedPodInfo) int32 {
	if pInfo.Pod.Spec.Priority == nil {
		return 0
	}
	return *pInfo.Pod.Spec.Priority
}

func encodeDescendingPriority(p int32) uint32 {
	normalized := uint32(p) ^ 0x80000000
	return ^normalized
}

func encodeActiveOrderKey(pInfo *framework.QueuedPodInfo) string {
	prPart := encodeDescendingPriority(priorityOf(pInfo))
	tsPart := pInfo.Timestamp.UnixMilli()
	uidPart := string(pInfo.Pod.UID)
	return fmt.Sprintf("%010d#%019d#%s", prPart, tsPart, uidPart)
}

func encodeBackoffOrderKey(backoffTime time.Time, uid types.UID) string {
	return fmt.Sprintf("%019d#%s", backoffTime.UnixMilli(), string(uid))
}

func encodeErrorBackoffOrderKey(backoffTime time.Time, uid types.UID) string {
	return fmt.Sprintf("%019d#%s", backoffTime.UnixMilli(), string(uid))
}

func avS(v string) dbtypes.AttributeValue {
	return &dbtypes.AttributeValueMemberS{Value: v}
}

func avN(v int64) dbtypes.AttributeValue {
	return &dbtypes.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

func avB(v []byte) dbtypes.AttributeValue {
	return &dbtypes.AttributeValueMemberB{Value: v}
}

func parseInt64Attr(item map[string]dbtypes.AttributeValue, name string) (int64, error) {
	av, ok := item[name].(*dbtypes.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("attribute %q missing or not numeric", name)
	}
	return strconv.ParseInt(av.Value, 10, 64)
}

func isConditionalFailure(err error) bool {
	var ccfe *dbtypes.ConditionalCheckFailedException
	return errors.As(err, &ccfe)
}

func upperBoundBackoffOrderKey(cutoff time.Time) string {
	// '~' sorts after typical UID characters.
	return fmt.Sprintf("%019d#~", cutoff.UnixMilli())
}
