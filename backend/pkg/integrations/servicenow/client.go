package servicenow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

type Client struct {
	InstanceURL string
	Username    string
	Password    string
}

func NewClient(instanceURL, username, password string) *Client {
	return &Client{
		InstanceURL: instanceURL,
		Username:    username,
		Password:    password,
	}
}

func (c *Client) CreateIncident(ctx context.Context, title string, desc string, urgency string) error {
	url := fmt.Sprintf("%s/api/now/table/incident", c.InstanceURL)

	payload := map[string]interface{}{
		"short_description": title,
		"description":       desc,
		"urgency":           urgency, // 1 = High, 2 = Medium, 3 = Low
		"impact":            urgency,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal servicenow payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("servicenow api returned status %d", resp.StatusCode)
	}

	logrus.WithFields(logrus.Fields{
		"title":   title,
		"urgency": urgency,
	}).Info("Successfully created ServiceNow incident")

	return nil
}
