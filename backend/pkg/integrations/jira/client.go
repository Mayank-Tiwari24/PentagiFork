package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

type Client struct {
	BaseURL  string
	APIToken string
	Email    string
	Project  string
}

func NewClient(baseURL, email, apiToken, project string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Email:    email,
		APIToken: apiToken,
		Project:  project,
	}
}

func (c *Client) CreateIssue(ctx context.Context, title string, desc string, severity string) error {
	url := fmt.Sprintf("%s/rest/api/2/issue", c.BaseURL)

	// Minimal Jira issue payload
	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{
				"key": c.Project,
			},
			"summary":     title,
			"description": desc,
			"issuetype": map[string]string{
				"name": "Task", // Typically "Bug" or "Task"
			},
			// Custom field for severity could be added here
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal jira payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.Email, c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("jira api returned status %d", resp.StatusCode)
	}

	logrus.WithFields(logrus.Fields{
		"project": c.Project,
		"title":   title,
	}).Info("Successfully created Jira issue")

	return nil
}
