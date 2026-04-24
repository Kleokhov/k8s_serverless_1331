package awsstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type SQSQueue interface {
	EnqueueAfter(ctx context.Context, body string, delay time.Duration) error
	Dequeue(ctx context.Context, maxMessages int32, visibilityTimeout time.Duration) ([]QueuedItem, error)
	Delete(ctx context.Context, receiptHandle string) error
}

type QueuedItem struct {
	MessageID     string
	Body          string
	ReceiptHandle string
}

type SQSQueueAWS struct {
	client         *sqs.Client
	queueURL       string
	isFIFO         bool
	messageGroupID string
}

type SQSQueueOption func(*SQSQueueAWS)

const (
	defaultFIFOMessageGroupID = "controller-queue"
	maxSQSReceiveBatchSize    = 10
)

func WithFIFOMessageGroupID(messageGroupID string) SQSQueueOption {
	return func(q *SQSQueueAWS) {
		if trimmed := strings.TrimSpace(messageGroupID); trimmed != "" {
			q.messageGroupID = trimmed
		}
	}
}

func NewSQSQueue(client *sqs.Client, queueURL string, opts ...SQSQueueOption) (*SQSQueueAWS, error) {
	queueURL = strings.TrimSpace(queueURL)
	if client == nil {
		return nil, fmt.Errorf("nil sqs client")
	}
	if queueURL == "" {
		return nil, fmt.Errorf("empty queue URL")
	}

	q := &SQSQueueAWS{
		client:         client,
		queueURL:       queueURL,
		isFIFO:         strings.HasSuffix(queueURL, ".fifo"),
		messageGroupID: defaultFIFOMessageGroupID,
	}
	for _, opt := range opts {
		opt(q)
	}

	return q, nil
}

func (q *SQSQueueAWS) EnqueueAfter(ctx context.Context, body string, delay time.Duration) error {
	return q.EnqueueAfterWithDeduplicationID(ctx, body, body, delay)
}

func (q *SQSQueueAWS) EnqueueAfterWithDeduplicationID(
	ctx context.Context,
	body string,
	deduplicationID string,
	delay time.Duration,
) error {
	if body == "" {
		return fmt.Errorf("empty message body")
	}

	input := &sqs.SendMessageInput{
		QueueUrl:     aws.String(q.queueURL),
		MessageBody:  aws.String(body),
		DelaySeconds: clampSQSSeconds(delay),
	}

	if q.isFIFO {
		if strings.TrimSpace(deduplicationID) == "" {
			deduplicationID = body
		}
		sum := sha256.Sum256([]byte(deduplicationID))
		input.MessageGroupId = aws.String(q.messageGroupID)
		input.MessageDeduplicationId = aws.String(hex.EncodeToString(sum[:]))
	}

	if _, err := q.client.SendMessage(ctx, input); err != nil {
		return fmt.Errorf("send sqs message: %w", err)
	}
	return nil
}

func (q *SQSQueueAWS) Dequeue(ctx context.Context, maxMessages int32, visibilityTimeout time.Duration) ([]QueuedItem, error) {
	maxMessages = normalizeReceiveBatchSize(maxMessages)

	out, err := q.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(q.queueURL),
		MaxNumberOfMessages: maxMessages,
		VisibilityTimeout:   clampSQSSeconds(visibilityTimeout),
		WaitTimeSeconds:     0,
	})
	if err != nil {
		return nil, fmt.Errorf("receive sqs messages: %w", err)
	}

	items := make([]QueuedItem, 0, len(out.Messages))
	for _, msg := range out.Messages {
		items = append(items, QueuedItem{
			MessageID:     aws.ToString(msg.MessageId),
			Body:          aws.ToString(msg.Body),
			ReceiptHandle: aws.ToString(msg.ReceiptHandle),
		})
	}
	return items, nil
}

func (q *SQSQueueAWS) Delete(ctx context.Context, receiptHandle string) error {
	if receiptHandle == "" {
		return fmt.Errorf("empty receipt handle")
	}
	if _, err := q.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(q.queueURL),
		ReceiptHandle: aws.String(receiptHandle),
	}); err != nil {
		return fmt.Errorf("delete sqs message: %w", err)
	}
	return nil
}

func normalizeReceiveBatchSize(size int32) int32 {
	if size <= 0 {
		return maxSQSReceiveBatchSize
	}
	if size > maxSQSReceiveBatchSize {
		return maxSQSReceiveBatchSize
	}
	return size
}

func clampSQSSeconds(d time.Duration) int32 {
	if d <= 0 {
		return 0
	}
	seconds := int32(math.Ceil(d.Seconds()))
	if seconds > 900 {
		return 900
	}
	return seconds
}
