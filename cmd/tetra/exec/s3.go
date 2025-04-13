package exec

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
)

func getS3Model(ctx context.Context, s3Client *s3.Client, bucket, lastKey string, namespaces []string) (*appModelV1.ApplicationModelEvent, error) {
	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(lastKey),
	})
	if err != nil {
		return nil, fmt.Errorf("getObject error: %w", err)
	}
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("object ReadAll error: %w", err)
	}
	reader := bytes.NewReader(body)
	gzreader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip reader error: %w", err)
	}
	bytes, err := io.ReadAll(gzreader)
	if err != nil {
		return nil, fmt.Errorf("appmodel reader error: %w", err)
	}
	models := strings.Split(string(bytes), "\n")
	appModel := models[len(models)-1]

	event := &appModelV1.ApplicationModelEvent{}
	decoder := json.NewDecoder(strings.NewReader(appModel))
	if err := decoder.Decode(event); err != nil {
		return nil, err
	}

	if len(namespaces) == 0 {
		return event, nil
	}

	filteredNS := []*appModelV1.ApplicationNamespace{}
	for _, ns := range event.ApplicationModel.Namespaces {
		for _, filter := range namespaces {
			if filter == ns.Name {
				filteredNS = append(filteredNS, ns)
			}
		}
	}
	event.ApplicationModel.Host = nil
	event.ApplicationModel.Namespaces = filteredNS
	return event, nil
}

func s3GetLastKey(ctx context.Context, s3Client *s3.Client, bucket, lastKey string) (string, error) {
	var err error
	var output *s3.ListObjectsV2Output

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	}

	if lastKey != "" {
		input.StartAfter = &lastKey
	}

	var objects []types.Object
	objectPaginator := s3.NewListObjectsV2Paginator(s3Client, input)
	for objectPaginator.HasMorePages() {
		output, err = objectPaginator.NextPage(ctx)
		if err != nil {
			var noBucket *types.NoSuchBucket
			if errors.As(err, &noBucket) {
				return "", error(noBucket)
			}
			break
		}
		objects = append(objects, output.Contents...)
	}

	var objKeys []string
	for _, object := range objects {
		objKeys = append(objKeys, *object.Key)
	}

	// If objectKeys == 0 then there are no new objects in the bucket
	if len(objKeys) > 0 {
		return objKeys[len(objKeys)-1], nil
	}
	return "", nil
}
