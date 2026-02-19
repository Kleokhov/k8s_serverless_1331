package dynamo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/value"
)

// Scheme
const (
	attrPK = "pk"
	attrSK = "sk"

	// user object attributes
	attrData = "data" // Binary
	attrRV   = "rv"   // Number (uint64 as string)
	attrTTL  = "ttl"  // Number (epoch seconds, optional)

	// meta row
	metaPK        = "__meta__"
	metaSK        = "__meta__"
	attrCurrentRV = "current_rv" // Number (uint64 as string)

	pkV1Constant = "p0"
	minInitialRV = uint64(1)
	ttlAttribute = attrTTL
)

type authenticatedDataString string

// AuthenticatedData implements the value.Context interface.
func (d authenticatedDataString) AuthenticatedData() []byte {
	return []byte(string(d))
}

var _ value.Context = authenticatedDataString("")

type store struct {
	ddb           *dynamodb.Client
	codec         runtime.Codec
	versioner     storage.Versioner
	transformer   value.Transformer
	pathPrefix    string
	groupResource schema.GroupResource
	decoder       Decoder

	resourcePrefix string
	tableName      string
}

type objState struct {
	obj   runtime.Object
	rev   uint64
	data  []byte
	stale bool
	meta  storage.ResponseMeta
}

var _ storage.Interface = (*store)(nil)

// New constructs a DynamoDB store for one resource table.
// If bootstrap==true, it will CreateTable (if missing), enable TTL best-effort, and create the meta row.
func New(
	ctx context.Context,
	ddb *dynamodb.Client,
	tableName string,
	prefix string,
	resourcePrefix string,
	groupResource schema.GroupResource,
	versioner storage.Versioner,
	transformer value.Transformer,
	decoder Decoder,
	codec runtime.Codec,
	bootstrap bool,
) (*store, error) {
	pathPrefix := path.Join("/", prefix)
	if !strings.HasSuffix(pathPrefix, "/") {
		pathPrefix += "/"
	}
	if resourcePrefix == "" || resourcePrefix == "/" {
		// Derive something stable so we don't crash on synthetic/internal resources.
		// groupResource.String() is e.g. "apiServerIPInfo" or "endpoints".
		gr := groupResource.String()
		if gr == "" {
			gr = "unknown"
		}
		resourcePrefix = "/" + gr
	}
	if !strings.HasPrefix(resourcePrefix, "/") {
		return nil, fmt.Errorf("resourcePrefix needs to start from /")
	}

	s := &store{
		ddb:            ddb,
		tableName:      tableName,
		pathPrefix:     pathPrefix,
		resourcePrefix: resourcePrefix,
		groupResource:  groupResource,
		versioner:      versioner,
		transformer:    transformer,
		decoder:        decoder,
		codec:          codec,
	}

	if bootstrap {
		if err := EnsureResourceTable(ctx, ddb, tableName); err != nil {
			return nil, err
		}
		if err := ensureMetaRow(ctx, ddb, tableName); err != nil {
			return nil, err
		}
		fmt.Println("DynamoDB storage backend bootstrapped successfully.")
	}

	return s, nil
}

// EnsureResourceTable creates the per-resource table if it does not exist.
// It also enables TTL on attribute "ttl" best-effort (ignores errors that indicate it's already set).
func EnsureResourceTable(ctx context.Context, ddb *dynamodb.Client, tableName string) error {
	// Fast path: already exists.
	_, err := ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)})
	if err == nil {
		return nil
	}
	var rnfe *ddbtypes.ResourceNotFoundException
	if !errors.As(err, &rnfe) {
		return fmt.Errorf("DescribeTable(%s): %w", tableName, err)
	}

	_, err = ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(tableName),
		BillingMode: ddbtypes.BillingModePayPerRequest,
		AttributeDefinitions: []ddbtypes.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: ddbtypes.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrSK), AttributeType: ddbtypes.ScalarAttributeTypeS},
		},
		KeySchema: []ddbtypes.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: ddbtypes.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: ddbtypes.KeyTypeRange},
		},
	})
	if err != nil {
		return fmt.Errorf("CreateTable(%s): %w", tableName, err)
	}

	waiter := dynamodb.NewTableExistsWaiter(ddb)
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := waiter.Wait(waitCtx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 15*time.Second); err != nil {
		return fmt.Errorf("wait for table %s to exist: %w", tableName, err)
	}

	// TODO: double-check TTL expiration
	// Best-effort TTL enablement (safe to ignore failures if permissions not granted).
	_, _ = ddb.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(tableName),
		TimeToLiveSpecification: &ddbtypes.TimeToLiveSpecification{
			AttributeName: aws.String(ttlAttribute),
			Enabled:       aws.Bool(true),
		},
	})

	return nil
}

// ensureMetaRow creates the meta row if it doesn't exist.
func ensureMetaRow(ctx context.Context, ddb *dynamodb.Client, tableName string) error {
	// Create meta row if it doesn't exist.
	_, err := ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item: map[string]ddbtypes.AttributeValue{
			attrPK:        &ddbtypes.AttributeValueMemberS{Value: metaPK},
			attrSK:        &ddbtypes.AttributeValueMemberS{Value: metaSK},
			attrCurrentRV: &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(minInitialRV, 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK,
		},
	})
	if err == nil {
		return nil
	}
	var cfe *ddbtypes.ConditionalCheckFailedException
	if errors.As(err, &cfe) {
		// already exists
		return nil
	}
	return fmt.Errorf("PutItem(meta row) table=%s: %w", tableName, err)
}

// validateMinimumResourceVersion returns a 'too large resource' version error when the provided minimumResourceVersion is
// greater than the most recent actualRevision available from storage.
func (s *store) validateMinimumResourceVersion(minimumResourceVersion string, actualRevision uint64) error {
	if minimumResourceVersion == "" {
		return nil
	}
	minimumRV, err := s.versioner.ParseResourceVersion(minimumResourceVersion)
	if err != nil {
		return apierrors.NewBadRequest(fmt.Sprintf("invalid resource version: %v", err))
	}
	// Enforce the storage.Interface guarantee that the resource version of the returned data
	// "will be at least 'resourceVersion'".
	if minimumRV > actualRevision {
		return storage.NewTooLargeResourceVersionError(minimumRV, actualRevision, 0)
	}
	return nil
}

// getCurrentObjectState loads the object row (consistent), filters TTL-expired items as NotFound,
// decrypts, decodes into a freshly allocated object, and returns (obj, rev, data).
func (s *store) getCurrentObjectState(ctx context.Context, preparedKey string, v reflect.Value) (*objState, error) {
	resp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.tableName),
		ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{
			attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
			attrSK: &ddbtypes.AttributeValueMemberS{Value: preparedKey},
		},
	})
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("GetItem(%s): %w", preparedKey, err))
	}
	if len(resp.Item) == 0 {
		return nil, storage.NewKeyNotFoundError(preparedKey, 0)
	}

	// Prefer uint parse to avoid negative wrap.
	modRevU, err := parseRV(resp.Item, attrRV)
	if err != nil {
		return nil, storage.NewInternalError(fmt.Errorf("parse %s: %w", attrRV, err))
	}
	modRevI, err := rvToInt64(modRevU)
	if err != nil {
		return nil, storage.NewInternalError(err)
	}

	ciphertext, err := parseBinaryAttr(resp.Item, attrData)
	if err != nil {
		return nil, storage.NewInternalError(err)
	}
	plaintext, stale, err := s.transformer.TransformFromStorage(ctx, ciphertext, authenticatedDataString(preparedKey))
	if err != nil {
		return nil, storage.NewInternalError(err)
	}

	var obj runtime.Object
	if u, ok := v.Addr().Interface().(runtime.Unstructured); ok {
		obj = u.NewEmptyInstance()
	} else {
		obj = reflect.New(v.Type()).Interface().(runtime.Object)
	}

	if err := s.decoder.Decode(plaintext, obj, modRevI); err != nil {
		return nil, err
	}

	return &objState{
		obj:   obj,
		rev:   modRevU,
		data:  plaintext,
		stale: stale,
		meta:  storage.ResponseMeta{ResourceVersion: modRevU},
	}, nil
}

// getCurrentRV reads the meta row and returns current_rv.
func (s *store) getCurrentRV(ctx context.Context) (uint64, error) {
	resp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]ddbtypes.AttributeValue{
			attrPK: &ddbtypes.AttributeValueMemberS{Value: metaPK},
			attrSK: &ddbtypes.AttributeValueMemberS{Value: metaSK},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return 0, fmt.Errorf("GetItem(meta): %w", err)
	}
	if len(resp.Item) == 0 {
		return 0, fmt.Errorf("meta row not found in table %q", s.tableName)
	}
	cur, err := parseRV(resp.Item, attrCurrentRV)
	if err != nil {
		return 0, err
	}
	return cur, nil
}

func (s *store) updateState(st *objState, userUpdate storage.UpdateFunc) (runtime.Object, error) {
	ret, _, err := userUpdate(st.obj, st.meta)
	if err != nil {
		return nil, err
	}
	if err := s.versioner.PrepareObjectForStorage(ret); err != nil {
		return nil, fmt.Errorf("PrepareObjectForStorage failed: %v", err)
	}
	return ret, nil
}

func (s *store) prepareKey(key string, recursive bool) (string, error) {
	if key == ".." ||
		strings.HasPrefix(key, "../") ||
		strings.HasSuffix(key, "/..") ||
		strings.Contains(key, "/../") {
		return "", fmt.Errorf("invalid key: %q", key)
	}
	if key == "." ||
		strings.HasPrefix(key, "./") ||
		strings.HasSuffix(key, "/.") ||
		strings.Contains(key, "/./") {
		return "", fmt.Errorf("invalid key: %q", key)
	}
	if key == "" || key == "/" {
		return "", fmt.Errorf("empty key: %q", key)
	}
	// We ensured that pathPrefix ends in '/' in construction, so skip any leading '/' in the key now.
	startIndex := 0
	if key[0] == '/' {
		startIndex = 1
	}
	return s.pathPrefix + key[startIndex:], nil
}

// Versioner implements storage.Interface.Versioner.
func (s *store) Versioner() storage.Versioner {
	return s.versioner
}

// Get implements storage.Interface.Get.
// TODO: May need to add retry logic for TransactionCanceledException
// TODO: Consider adding TTL support
func (s *store) Get(ctx context.Context, key string, opts storage.GetOptions, out runtime.Object) error {
	preparedKey, err := s.prepareKey(key, false)
	if err != nil {
		return err
	}

	// If caller doesn't ask for a minimum RV, we don't need meta.
	if opts.ResourceVersion == "" {
		resp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: aws.String(s.tableName),
			Key: map[string]ddbtypes.AttributeValue{
				attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
				attrSK: &ddbtypes.AttributeValueMemberS{Value: preparedKey},
			},
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return storage.NewInternalError(fmt.Errorf("GetItem: %w", err))
		}
		if len(resp.Item) == 0 {
			if opts.IgnoreNotFound {
				return runtime.SetZeroValue(out)
			}
			return storage.NewKeyNotFoundError(preparedKey, 0)
		}

		ciphertext, err := parseBinaryAttr(resp.Item, attrData)
		if err != nil {
			return storage.NewInternalError(err)
		}
		plaintext, _, err := s.transformer.TransformFromStorage(ctx, ciphertext, authenticatedDataString(preparedKey))
		if err != nil {
			return storage.NewInternalError(err)
		}
		rvU, err := parseRV(resp.Item, attrRV)
		if err != nil {
			return storage.NewInternalError(fmt.Errorf("parse %s: %w", attrRV, err))
		}
		rvI, err := rvToInt64(rvU)
		if err != nil {
			return storage.NewInternalError(err)
		}
		return s.decoder.Decode(plaintext, out, rvI)
	}

	// ResourceVersion constraint present: read object + meta as one consistent snapshot.
	resp, err := s.ddb.TransactGetItems(ctx, &dynamodb.TransactGetItemsInput{
		TransactItems: []ddbtypes.TransactGetItem{
			{
				Get: &ddbtypes.Get{
					TableName: aws.String(s.tableName),
					Key: map[string]ddbtypes.AttributeValue{
						attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
						attrSK: &ddbtypes.AttributeValueMemberS{Value: preparedKey},
					},
				},
			},
			{
				Get: &ddbtypes.Get{
					TableName: aws.String(s.tableName),
					Key: map[string]ddbtypes.AttributeValue{
						attrPK: &ddbtypes.AttributeValueMemberS{Value: metaPK},
						attrSK: &ddbtypes.AttributeValueMemberS{Value: metaSK},
					},
				},
			},
		},
	})
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("TransactGetItems: %w", err))
	}
	if len(resp.Responses) != 2 {
		return storage.NewInternalError(fmt.Errorf("TransactGetItems: expected 2 responses, got %d", len(resp.Responses)))
	}

	objItem := resp.Responses[0].Item
	metaItem := resp.Responses[1].Item

	actualRevision, err := parseRV(metaItem, attrCurrentRV)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("meta %s parse: %w", attrCurrentRV, err))
	}
	if actualRevision == 0 {
		return storage.NewInternalError(fmt.Errorf("meta %s must be > 0", attrCurrentRV))
	}
	if err := s.validateMinimumResourceVersion(opts.ResourceVersion, actualRevision); err != nil {
		return err
	}

	if len(objItem) == 0 {
		if opts.IgnoreNotFound {
			return runtime.SetZeroValue(out)
		}
		return storage.NewKeyNotFoundError(preparedKey, 0)
	}

	ciphertext, err := parseBinaryAttr(objItem, attrData)
	if err != nil {
		return storage.NewInternalError(err)
	}
	plaintext, _, err := s.transformer.TransformFromStorage(ctx, ciphertext, authenticatedDataString(preparedKey))
	if err != nil {
		return storage.NewInternalError(err)
	}
	rvU, err := parseRV(objItem, attrRV)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("parse %s: %w", attrRV, err))
	}
	rvI, err := rvToInt64(rvU)
	if err != nil {
		return storage.NewInternalError(err)
	}
	return s.decoder.Decode(plaintext, out, rvI)
}

// GetList implements storage.Interface.GetList.
// TODO: Consider adding TTL support
func (s *store) GetList(ctx context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	keyPrefix, err := s.prepareKey(key, opts.Recursive)
	if err != nil {
		return err
	}

	listPtr, err := meta.GetItemsPtr(listObj)
	if err != nil {
		return err
	}
	vPtr, err := conversion.EnforcePtr(listPtr)
	if err != nil || vPtr.Kind() != reflect.Slice {
		return fmt.Errorf("need ptr to slice: %v", err)
	}

	// page/bucket target
	limit := opts.Predicate.Limit
	paging := limit > 0

	// Allocate new item values for decoding
	newItem := func() runtime.Object {
		elem := vPtr.Type().Elem()
		if elem.Kind() == reflect.Ptr {
			return reflect.New(elem.Elem()).Interface().(runtime.Object)
		}
		return reflect.New(elem).Interface().(runtime.Object)
	}
	appendItem := func(obj runtime.Object) {
		elem := vPtr.Type().Elem()
		ov := reflect.ValueOf(obj)
		if elem.Kind() == reflect.Ptr {
			vPtr.Set(reflect.Append(vPtr, ov))
			return
		}
		vPtr.Set(reflect.Append(vPtr, ov.Elem()))
	}

	// Parse RV/continue semantics the same way the etcd store does.
	// - If continue token is set, opts.ResourceVersion must be empty (or "0").
	withRev, continueKey, err := storage.ValidateListOptions(keyPrefix, s.versioner, opts)
	if err != nil {
		return err
	}

	// Anchor the list at a single "current_rv" snapshot point (best-effort).
	actualRV, err := s.getCurrentRV(ctx)
	if err != nil {
		return storage.NewInternalError(err)
	}
	if err := s.validateMinimumResourceVersion(opts.ResourceVersion, actualRV); err != nil {
		return err
	}

	// Decide the RV we will return on the list object.
	// For NotOlderThan, ValidateListOptions leaves withRev==0, and etcd sets it to the response revision later.
	// For Dynamo, we peg it to current_rv once.
	var listRV uint64
	if withRev <= 0 {
		listRV = actualRV
	} else {
		listRV = uint64(withRev)
		if listRV > actualRV {
			return storage.NewTooLargeResourceVersionError(listRV, actualRV, 0)
		}
	}

	// Trim the "\x00" suffix from continueKey (etcd uses lastKey+"\x00" as the next start key).
	// DecodeContinue returns exactly what was encoded.
	trimStartAfter := func(k string) string {
		return strings.TrimSuffix(k, "\x00")
	}

	// Fast path for non-recursive: exact key match (like etcd getList non-recursive).
	if !opts.Recursive {
		resp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
			TableName:      aws.String(s.tableName),
			ConsistentRead: aws.Bool(true),
			Key: map[string]ddbtypes.AttributeValue{
				attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
				attrSK: &ddbtypes.AttributeValueMemberS{Value: keyPrefix},
			},
			ProjectionExpression: aws.String("#sk,#rv,#data"),
			ExpressionAttributeNames: map[string]string{
				"#sk":   attrSK,
				"#rv":   attrRV,
				"#data": attrData,
			},
		})
		if err != nil {
			return storage.NewInternalError(fmt.Errorf("GetItem(%s): %w", keyPrefix, err))
		}
		if len(resp.Item) == 0 {
			// empty list at listRV
			if vPtr.IsNil() {
				vPtr.Set(reflect.MakeSlice(vPtr.Type(), 0, 0))
			}
			return s.versioner.UpdateList(listObj, listRV, "", nil)
		}

		itemRV, err := parseRV(resp.Item, attrRV)
		if err != nil {
			return storage.NewInternalError(err)
		}
		// best-effort snapshot filter
		if itemRV <= listRV {
			ciphertext, err := parseBinaryAttr(resp.Item, attrData)
			if err != nil {
				return storage.NewInternalError(err)
			}
			plaintext, _, err := s.transformer.TransformFromStorage(ctx, ciphertext, authenticatedDataString(keyPrefix))
			if err != nil {
				return storage.NewInternalError(err)
			}
			rvI, err := rvToInt64(itemRV)
			if err != nil {
				return storage.NewInternalError(err)
			}
			obj := newItem()
			if err := s.decoder.Decode(plaintext, obj, rvI); err != nil {
				return err
			}
			matched, err := opts.Predicate.Matches(obj)
			if err != nil {
				return err
			}
			if matched {
				appendItem(obj)
			}
		}

		if vPtr.IsNil() {
			vPtr.Set(reflect.MakeSlice(vPtr.Type(), 0, 0))
		}
		return s.versioner.UpdateList(listObj, listRV, "", nil)
	}

	// Recursive list: Query(pk==p0 AND begins_with(sk, keyPrefix)).
	const (
		defaultPageSize = int64(1000)
		maxPageSize     = int64(10000)
	)

	pageSize := defaultPageSize
	if paging {
		pageSize = limit
		if pageSize <= 0 {
			pageSize = defaultPageSize
		}
		if pageSize > maxPageSize {
			pageSize = maxPageSize
		}
	}

	var lastKey string
	var hasMore bool

	// We must page through Dynamo even if !paging, because responses are size-limited.
	var exclusiveStartKey map[string]ddbtypes.AttributeValue
	if continueKey != "" {
		startAfter := trimStartAfter(continueKey)
		if startAfter != "" {
			exclusiveStartKey = map[string]ddbtypes.AttributeValue{
				attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
				attrSK: &ddbtypes.AttributeValueMemberS{Value: startAfter},
			}
		}
	}

	for {
		// If request timed out/canceled, stop early.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		lim := pageSize
		if lim > maxPageSize {
			lim = maxPageSize
		}

		q := &dynamodb.QueryInput{
			TableName:              aws.String(s.tableName),
			ConsistentRead:         aws.Bool(true),
			KeyConditionExpression: aws.String("#pk = :pk AND begins_with(#sk, :prefix)"),
			ExpressionAttributeNames: map[string]string{
				"#pk":   attrPK,
				"#sk":   attrSK,
				"#rv":   attrRV,
				"#data": attrData,
			},
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":pk":     &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
				":prefix": &ddbtypes.AttributeValueMemberS{Value: keyPrefix},
			},
			ProjectionExpression: aws.String("#sk,#rv,#data"),
			ScanIndexForward:     aws.Bool(true),
			Limit:                aws.Int32(int32(lim)),
			ExclusiveStartKey:    exclusiveStartKey,
		}

		resp, err := s.ddb.Query(ctx, q)
		if err != nil {
			return storage.NewInternalError(fmt.Errorf("Query(prefix=%q): %w", keyPrefix, err))
		}

		if len(resp.Items) == 0 && resp.LastEvaluatedKey != nil && len(resp.LastEvaluatedKey) > 0 {
			return fmt.Errorf("no results were found, but dynamodb indicated there were more values remaining")
		}

		// We'll use this unless we break early due to filling the client's limit.
		nextExclusiveStartKey := resp.LastEvaluatedKey
		hasMore = nextExclusiveStartKey != nil && len(nextExclusiveStartKey) > 0

		// Consume the page.
		for _, item := range resp.Items {
			// Track progress key even if the object is filtered out.
			sk, err := parseStringAttr(item, attrSK)
			if err != nil {
				return storage.NewInternalError(err)
			}
			lastKey = sk

			// If the client bucket is full, stop early and resume after lastKey.
			if paging && int64(vPtr.Len()) >= limit {
				hasMore = true
				nextExclusiveStartKey = map[string]ddbtypes.AttributeValue{
					attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
					attrSK: &ddbtypes.AttributeValueMemberS{Value: lastKey},
				}
				break
			}

			itemRV, err := parseRV(item, attrRV)
			if err != nil {
				return storage.NewInternalError(err)
			}
			// best-effort snapshot filter to keep item RVs <= list RV
			if itemRV > listRV {
				continue
			}

			ciphertext, err := parseBinaryAttr(item, attrData)
			if err != nil {
				return storage.NewInternalError(err)
			}
			plaintext, _, err := s.transformer.TransformFromStorage(ctx, ciphertext, authenticatedDataString(sk))
			if err != nil {
				return storage.NewInternalError(err)
			}

			rvI, err := rvToInt64(itemRV)
			if err != nil {
				return storage.NewInternalError(err)
			}

			obj := newItem()
			if err := s.decoder.Decode(plaintext, obj, rvI); err != nil {
				return err
			}

			matched, err := opts.Predicate.Matches(obj)
			if err != nil {
				return err
			}
			if matched {
				appendItem(obj)
			}
		}

		// Advance Dynamo paging cursor.
		exclusiveStartKey = nextExclusiveStartKey

		// Stop conditions (same shape as etcd loop):
		if !hasMore {
			break
		}
		if paging && int64(vPtr.Len()) >= limit {
			break
		}

		// If we’re paging but filtering dropped many objects, increase the underlying page size.
		if paging && int64(vPtr.Len()) < limit && pageSize < maxPageSize {
			pageSize *= 2
			if pageSize > maxPageSize {
				pageSize = maxPageSize
			}
		}
	}

	if vPtr.IsNil() {
		vPtr.Set(reflect.MakeSlice(vPtr.Type(), 0, 0))
	}

	// Continue token: use EncodeContinue directly so we can omit RemainingItemCount cleanly.
	// The key we encode should be the "next start key", which etcd represents as lastKey+"\x00".
	var continueValue string
	var remainingItemCount *int64 = nil
	if hasMore && lastKey != "" {
		cv, err := storage.EncodeContinue(lastKey+"\x00", keyPrefix, int64(listRV))
		if err != nil {
			return err
		}
		continueValue = cv
	}

	return s.versioner.UpdateList(listObj, listRV, continueValue, remainingItemCount)
}

// Create implements storage.Interface.Create.
// TODO: Improve error handling to distinguish KeyExists vs others.
// TODO: Consider adding TTL support
func (s *store) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	_ = ttl // ignored: TTL not supported

	preparedKey, err := s.prepareKey(key, false)
	if err != nil {
		return err
	}

	if version, err := s.versioner.ObjectResourceVersion(obj); err == nil && version != 0 {
		return storage.ErrResourceVersionSetOnCreate
	}
	if err := s.versioner.PrepareObjectForStorage(obj); err != nil {
		return fmt.Errorf("PrepareObjectForStorage failed: %v", err)
	}
	data, err := runtime.Encode(s.codec, obj)
	if err != nil {
		return err
	}
	newData, err := s.transformer.TransformToStorage(ctx, data, authenticatedDataString(preparedKey))
	if err != nil {
		return storage.NewInternalError(err)
	}

	const maxAttempts = 10
	for attempt := 0; attempt < maxAttempts; attempt++ {
		curRV, err := s.getCurrentRV(ctx)
		if err != nil {
			return storage.NewInternalError(err)
		}
		newRV := curRV + 1
		if newRV > maxRV { // > MaxInt64
			return storage.NewInternalError(fmt.Errorf("resource version overflow: %d", newRV))
		}

		item := map[string]ddbtypes.AttributeValue{
			attrPK:   &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
			attrSK:   &ddbtypes.AttributeValueMemberS{Value: preparedKey},
			attrData: &ddbtypes.AttributeValueMemberB{Value: newData},
			attrRV:   &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(newRV, 10)},
		}

		_, err = s.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []ddbtypes.TransactWriteItem{
				{
					Update: &ddbtypes.Update{
						TableName: aws.String(s.tableName),
						Key: map[string]ddbtypes.AttributeValue{
							attrPK: &ddbtypes.AttributeValueMemberS{Value: metaPK},
							attrSK: &ddbtypes.AttributeValueMemberS{Value: metaSK},
						},
						UpdateExpression:    aws.String("SET #crv = :new"),
						ConditionExpression: aws.String("#crv = :cur"),
						ExpressionAttributeNames: map[string]string{
							"#crv": attrCurrentRV,
						},
						ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
							":cur": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(curRV, 10)},
							":new": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(newRV, 10)},
						},
					},
				},
				{
					Put: &ddbtypes.Put{
						TableName:           aws.String(s.tableName),
						Item:                item,
						ConditionExpression: aws.String("attribute_not_exists(#sk)"),
						ExpressionAttributeNames: map[string]string{
							"#sk": attrSK,
						},
					},
				},
			},
		})
		if err == nil {
			if out != nil {
				if derr := s.decoder.Decode(data, out, int64(newRV)); derr != nil {
					return derr
				}
			}
			return nil
		}

		if isKeyExistsTxnError(err) {
			return storage.NewKeyExistsError(preparedKey, 0)
		}
		if isMetaConflictTxnError(err) {
			continue
		}
		return storage.NewInternalError(fmt.Errorf("TransactWriteItems(Create): %w", err))
	}

	return storage.NewInternalError(fmt.Errorf("create failed after %d retries due to concurrent writers", maxAttempts))
}

// Delete implements storage.Interface.Delete.
// cachedExistingObject always nil; ignored
// TODO: Improve error handling to distinguish NotFound vs conflict vs others.
// TODO: Consider adding TTL support
func (s *store) Delete(
	ctx context.Context,
	key string,
	out runtime.Object,
	preconditions *storage.Preconditions,
	validateDeletion storage.ValidateObjectFunc,
	_ runtime.Object,
	_ storage.DeleteOptions,
) error {
	preparedKey, err := s.prepareKey(key, false)
	if err != nil {
		return err
	}

	v, err := conversion.EnforcePtr(out)
	if err != nil {
		return fmt.Errorf("unable to convert output object to pointer: %v", err)
	}
	if validateDeletion == nil {
		validateDeletion = func(context.Context, runtime.Object) error { return nil }
	}

	const maxTxnAttempts = 10

	for {
		// Always read the current object state.
		origState, err := s.getCurrentObjectState(ctx, preparedKey, v)
		if err != nil {
			// includes NotFound
			return err
		}

		// Preconditions and validation are against a current read, so failures are definitive.
		if preconditions != nil {
			if err := preconditions.Check(preparedKey, origState.obj); err != nil {
				return err
			}
		}
		if err := validateDeletion(ctx, origState.obj); err != nil {
			return err
		}

		needReload := false

		// Try transactional delete (meta RV bump + conditional delete on per-object rv).
		for attempt := 0; attempt < maxTxnAttempts; attempt++ {
			curRV, err := s.getCurrentRV(ctx)
			if err != nil {
				return storage.NewInternalError(err)
			}
			newRV := curRV + 1
			if newRV > maxRV {
				return storage.NewInternalError(fmt.Errorf("resource version overflow: %d", newRV))
			}

			_, err = s.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
				TransactItems: []ddbtypes.TransactWriteItem{
					{
						Update: &ddbtypes.Update{
							TableName: aws.String(s.tableName),
							Key: map[string]ddbtypes.AttributeValue{
								attrPK: &ddbtypes.AttributeValueMemberS{Value: metaPK},
								attrSK: &ddbtypes.AttributeValueMemberS{Value: metaSK},
							},
							UpdateExpression:    aws.String("SET #crv = :new"),
							ConditionExpression: aws.String("#crv = :cur"),
							ExpressionAttributeNames: map[string]string{
								"#crv": attrCurrentRV,
							},
							ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
								":cur": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(curRV, 10)},
								":new": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(newRV, 10)},
							},
						},
					},
					{
						Delete: &ddbtypes.Delete{
							TableName: aws.String(s.tableName),
							Key: map[string]ddbtypes.AttributeValue{
								attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
								attrSK: &ddbtypes.AttributeValueMemberS{Value: preparedKey},
							},
							// Optimistic delete: only delete if per-object rv matches what we read.
							ConditionExpression: aws.String("#rv = :expected"),
							ExpressionAttributeNames: map[string]string{
								"#rv": attrRV,
							},
							ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
								":expected": &ddbtypes.AttributeValueMemberN{
									Value: strconv.FormatUint(origState.rev, 10),
								},
							},
						},
					},
				},
			})
			if err == nil {
				// Return the deleted object with the delete RV (newRV).
				if out != nil {
					if derr := s.decoder.Decode(origState.data, out, int64(newRV)); derr != nil {
						return derr
					}
				}
				return nil
			}

			// Meta row moved; retry inner loop (re-read curRV next iteration).
			if isMetaConflictTxnError(err) {
				continue
			}

			// Object delete condition failed: object changed or was deleted.
			// Reload object state and restart outer loop (re-check preconditions/validation on new state).
			if txnCanceledConditionalFailed(err, 1) {
				needReload = true
				break
			}

			return storage.NewInternalError(fmt.Errorf("TransactWriteItems(Delete): %w", err))
		}

		if needReload {
			// outer loop retry
			continue
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// GuaranteedUpdate implements storage.Interface.GuaranteedUpdate.
// cachedExistingObject always nil; ignored
// TODO: Improve error handling to distinguish NotFound vs conflict vs others.
// TODO: Consider adding TTL support
func (s *store) GuaranteedUpdate(
	ctx context.Context,
	key string,
	destination runtime.Object,
	ignoreNotFound bool,
	preconditions *storage.Preconditions,
	tryUpdate storage.UpdateFunc,
	_ runtime.Object,
) error {
	preparedKey, err := s.prepareKey(key, false)
	if err != nil {
		return err
	}

	v, err := conversion.EnforcePtr(destination)
	if err != nil {
		return fmt.Errorf("unable to convert output object to pointer: %v", err)
	}

	newEmpty := func() runtime.Object {
		if u, ok := v.Addr().Interface().(runtime.Unstructured); ok {
			return u.NewEmptyInstance()
		}
		return reflect.New(v.Type()).Interface().(runtime.Object)
	}

	getCurrentState := func() (*objState, error) {
		st, err := s.getCurrentObjectState(ctx, preparedKey, v)
		if err == nil {
			return st, nil
		}
		if (apierrors.IsNotFound(err) || storage.IsNotFound(err)) && ignoreNotFound {
			obj := newEmpty()
			if err := runtime.SetZeroValue(obj); err != nil {
				return nil, err
			}
			return &objState{
				obj:   obj,
				rev:   0,
				data:  nil,
				stale: false,
				meta:  storage.ResponseMeta{}, // TTL ignored
			}, nil
		}
		return nil, err
	}

	transformContext := authenticatedDataString(preparedKey)

	const maxMetaAttempts = 10

	for {
		origState, err := getCurrentState()
		if err != nil {
			return err
		}

		if preconditions != nil {
			if err := preconditions.Check(preparedKey, origState.obj); err != nil {
				return err
			}
		}

		ret, err := s.updateState(origState, tryUpdate)
		if err != nil {
			return err
		}

		data, err := runtime.Encode(s.codec, ret)
		if err != nil {
			return err
		}

		// No-op short circuit (same idea as etcd).
		if origState.rev != 0 && !origState.stale && bytes.Equal(data, origState.data) {
			// Decode from stored bytes, stamp with stored RV.
			if derr := s.decoder.Decode(origState.data, destination, int64(origState.rev)); derr != nil {
				return derr
			}
			return nil
		}

		newData, err := s.transformer.TransformToStorage(ctx, data, transformContext)
		if err != nil {
			return storage.NewInternalError(err)
		}

		needReload := false

		for attempt := 0; attempt < maxMetaAttempts; attempt++ {
			curRV, err := s.getCurrentRV(ctx)
			if err != nil {
				return storage.NewInternalError(err)
			}
			newRV := curRV + 1
			if newRV > maxRV {
				return storage.NewInternalError(fmt.Errorf("resource version overflow: %d", newRV))
			}

			var objWrite ddbtypes.TransactWriteItem
			if origState.rev == 0 {
				item := map[string]ddbtypes.AttributeValue{
					attrPK:   &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
					attrSK:   &ddbtypes.AttributeValueMemberS{Value: preparedKey},
					attrData: &ddbtypes.AttributeValueMemberB{Value: newData},
					attrRV:   &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(newRV, 10)},
				}
				objWrite = ddbtypes.TransactWriteItem{
					Put: &ddbtypes.Put{
						TableName:           aws.String(s.tableName),
						Item:                item,
						ConditionExpression: aws.String("attribute_not_exists(#sk)"),
						ExpressionAttributeNames: map[string]string{
							"#sk": attrSK,
						},
					},
				}
			} else {
				objWrite = ddbtypes.TransactWriteItem{
					Update: &ddbtypes.Update{
						TableName: aws.String(s.tableName),
						Key: map[string]ddbtypes.AttributeValue{
							attrPK: &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
							attrSK: &ddbtypes.AttributeValueMemberS{Value: preparedKey},
						},
						UpdateExpression:    aws.String("SET #data = :data, #rv = :newrv"),
						ConditionExpression: aws.String("#rv = :expected"),
						ExpressionAttributeNames: map[string]string{
							"#data": attrData,
							"#rv":   attrRV,
						},
						ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
							":data":     &ddbtypes.AttributeValueMemberB{Value: newData},
							":newrv":    &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(newRV, 10)},
							":expected": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(origState.rev, 10)},
						},
					},
				}
			}

			_, err = s.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
				TransactItems: []ddbtypes.TransactWriteItem{
					{
						Update: &ddbtypes.Update{
							TableName: aws.String(s.tableName),
							Key: map[string]ddbtypes.AttributeValue{
								attrPK: &ddbtypes.AttributeValueMemberS{Value: metaPK},
								attrSK: &ddbtypes.AttributeValueMemberS{Value: metaSK},
							},
							UpdateExpression:    aws.String("SET #crv = :new"),
							ConditionExpression: aws.String("#crv = :cur"),
							ExpressionAttributeNames: map[string]string{
								"#crv": attrCurrentRV,
							},
							ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
								":cur": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(curRV, 10)},
								":new": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(newRV, 10)},
							},
						},
					},
					objWrite,
				},
			})
			if err == nil {
				// Decode plaintext desired bytes but stamp with write RV (newRV).
				if derr := s.decoder.Decode(data, destination, int64(newRV)); derr != nil {
					return derr
				}
				return nil
			}

			if isMetaConflictTxnError(err) {
				continue
			}
			if txnCanceledConditionalFailed(err, 1) {
				needReload = true
				break
			}

			return storage.NewInternalError(fmt.Errorf("TransactWriteItems(GuaranteedUpdate): %w", err))
		}

		if needReload {
			// object changed; start over with a fresh read + tryUpdate
			continue
		}

		// Too many meta conflicts. Closest-to-etcd is retry-until-ctx with backoff.
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// Watch implements storage.Interface.Watch.
func (s *store) Watch(ctx context.Context, key string, opts storage.ListOptions) (watch.Interface, error) {
	// If you see watchlist requests (sendInitialEvents=true) and want client-go to fallback:
	if opts.SendInitialEvents != nil && *opts.SendInitialEvents {
		// IMPORTANT: return an APIStatus error, not errors.New(...)
		return nil, apierrors.NewMethodNotSupported(s.groupResource, "watchlist/sendInitialEvents")
	}

	// No-op watch: never produces events, but doesn't error.
	// Keeps informers from crashing the server during bring-up.
	fw := watch.NewRaceFreeFake()

	go func() {
		<-ctx.Done()
		fw.Stop()
	}()

	return fw, nil
}

// ReadinessCheck implements storage.Interface.ReadinessCheck.
func (s *store) ReadinessCheck() error {
	return nil
}

// RequestWatchProgress implements storage.Interface.RequestWatchProgress.
func (s *store) RequestWatchProgress(ctx context.Context) error {
	return nil
}

// GetCurrentResourceVersion implements storage.Interface.GetCurrentResourceVersion.
func (s *store) GetCurrentResourceVersion(ctx context.Context) (uint64, error) {
	return 1, fmt.Errorf("not Implemented")
}

// CompactRevision implements storage.Interface.CompactRevision.
func (s *store) CompactRevision() int64 {
	return 0
}

func (s *store) Count(key string) (int64, error) {
	preparedKey, err := s.prepareKey(key, true)
	if err != nil {
		return 0, err
	}

	// Extra safety (matches etcd-store behavior too):
	// ensure "/a" doesn't also count "/ab".
	if !strings.HasSuffix(preparedKey, "/") {
		preparedKey += "/"
	}

	ctx := context.Background()

	var total int64
	var exclusiveStartKey map[string]ddbtypes.AttributeValue

	for {
		resp, err := s.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(s.tableName),
			ConsistentRead:         aws.Bool(true), // closest to etcd linearizable reads
			KeyConditionExpression: aws.String("#pk = :pk AND begins_with(#sk, :prefix)"),
			ExpressionAttributeNames: map[string]string{
				"#pk": attrPK,
				"#sk": attrSK,
			},
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":pk":     &ddbtypes.AttributeValueMemberS{Value: pkV1Constant},
				":prefix": &ddbtypes.AttributeValueMemberS{Value: preparedKey},
			},
			Select:            ddbtypes.SelectCount,
			ExclusiveStartKey: exclusiveStartKey,
		})
		if err != nil {
			return 0, storage.NewInternalError(fmt.Errorf("QueryCount(prefix=%q): %w", preparedKey, err))
		}

		total += int64(resp.Count)

		if resp.LastEvaluatedKey == nil || len(resp.LastEvaluatedKey) == 0 {
			break
		}
		exclusiveStartKey = resp.LastEvaluatedKey
	}

	return total, nil
}
