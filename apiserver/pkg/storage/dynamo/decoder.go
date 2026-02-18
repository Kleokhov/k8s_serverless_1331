package dynamo

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
)

type Decoder interface {
	// Decode decodes value of bytes into object. It will also
	// set the object resource version to rev.
	// On success, objPtr would be set to the object.
	Decode(value []byte, objPtr runtime.Object, rev int64) error

	// DecodeListItem decodes bytes value in array into object.
	DecodeListItem(ctx context.Context, data []byte, rev uint64, newItemFunc func() runtime.Object) (runtime.Object, error)
}
