package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBodySize = 1 << 20 // 1 MiB

// deliveryBudget stays under GitHub's 10s webhook timeout. Recipients are
// notified in parallel so one slow send does not use the whole budget.
const deliveryBudget = 9 * time.Second

type Config struct {
	Port      string
	SignalAPI string
	Routes    []Route
}

const (
	kindGitHub  = "github"
	kindGeneric = "generic"
	kindAlert   = "alert"
	kindMap     = "map"

	verifyHMAC  = "hmac"
	verifyToken = "token"
)

// Route is one webhook endpoint and the Signal chats it notifies.
type Route struct {
	Name       string
	Kind       string
	Path       string
	Secret     string
	Recipients []string
	Verify     string
	Header     string
	Prefix     string
	Title      string
	Fields     []string
	Match      []mapRule
}

type routeFile struct {
	Routes []routeSpec `json:"routes"`
}

type routeSpec struct {
	Name          string        `json:"name"`
	Kind          string        `json:"kind"`
	Path          string        `json:"path"`
	Secret        string        `json:"secret"`
	SecretEnv     string        `json:"secretEnv"`
	Recipients    []string      `json:"recipients"`
	RecipientsEnv string        `json:"recipientsEnv"`
	Verify        string        `json:"verify"`
	Header        string        `json:"header"`
	Prefix        string        `json:"prefix"`
	Title         string        `json:"title"`
	Fields        []string      `json:"fields"`
	Match         []mapRuleSpec `json:"match"`
}

type mapFieldSpec struct {
	Label      string `json:"label"`
	Path       string `json:"path"`
	TrimPrefix string `json:"trimPrefix"`
}

type mapEachSpec struct {
	Path   string `json:"path"`
	Text   string `json:"text"`
	Detail string `json:"detail"`
	Limit  int    `json:"limit"`
	Short  int    `json:"short"`
}

type mapRuleSpec struct {
	When      map[string]string `json:"when"`
	Present   []string          `json:"present"`
	Ignore    []string          `json:"ignore"`
	Status    string            `json:"status"`
	StatusMap map[string]string `json:"statusMap"`
	Title     string            `json:"title"`
	Subject   string            `json:"subject"`
	Summary   string            `json:"summary"`
	Fields    []mapFieldSpec    `json:"fields"`
	Each      *mapEachSpec      `json:"each"`
	Link      string            `json:"link"`
}

type mapField struct {
	Label      string
	Path       string
	TrimPrefix string
}

type mapEach struct {
	Path   string
	Text   string
	Detail string
	Limit  int
	Short  int
}

type mapRule struct {
	When      map[string]string
	Present   []string
	Ignore    []string
	Status    string
	StatusMap map[string]string
	Title     string
	Subject   string
	Summary   string
	Fields    []mapField
	Each      *mapEach
	Link      string
}

type deliveryFailure struct {
	recipient string
	err       error
}

type repository struct {
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
}

type actor struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type pushPayload struct {
	Ref        string     `json:"ref"`
	Compare    string     `json:"compare"`
	Pusher     actor      `json:"pusher"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
	Commits    []Commit   `json:"commits"`
}

type workflowRunPayload struct {
	Action      string `json:"action"`
	WorkflowRun struct {
		Name         string `json:"name"`
		HTMLURL      string `json:"html_url"`
		Status       string `json:"status"`
		Conclusion   string `json:"conclusion"`
		Event        string `json:"event"`
		HeadBranch   string `json:"head_branch"`
		DisplayTitle string `json:"display_title"`
		Actor        actor  `json:"actor"`
	} `json:"workflow_run"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type checkRunPayload struct {
	Action   string `json:"action"`
	CheckRun struct {
		Name       string `json:"name"`
		HTMLURL    string `json:"html_url"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		HeadSHA    string `json:"head_sha"`
		CheckSuite struct {
			HeadBranch string `json:"head_branch"`
		} `json:"check_suite"`
	} `json:"check_run"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type pageBuildPayload struct {
	Build struct {
		Status string `json:"status"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
		Commit string `json:"commit"`
		Pusher actor  `json:"pusher"`
	} `json:"build"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type deploymentStatusPayload struct {
	DeploymentStatus struct {
		State       string `json:"state"`
		Description string `json:"description"`
		TargetURL   string `json:"target_url"`
		Environment string `json:"environment"`
		LogURL      string `json:"log_url"`
	} `json:"deployment_status"`
	Deployment struct {
		Environment string `json:"environment"`
		Ref         string `json:"ref"`
		SHA         string `json:"sha"`
		Description string `json:"description"`
	} `json:"deployment"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type pullRequestPayload struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		Merged  bool   `json:"merged"`
		User    actor  `json:"user"`
		Head    struct {
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type releasePayload struct {
	Action  string `json:"action"`
	Release struct {
		TagName    string `json:"tag_name"`
		Name       string `json:"name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Author     actor  `json:"author"`
	} `json:"release"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type issuesPayload struct {
	Action string `json:"action"`
	Issue  struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		User    actor  `json:"user"`
	} `json:"issue"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type createDeletePayload struct {
	Ref        string     `json:"ref"`
	RefType    string     `json:"ref_type"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type starPayload struct {
	Action     string     `json:"action"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type forkPayload struct {
	Forkee struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"forkee"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type RPCResponse struct {
	Error json.RawMessage `json:"error"`
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func normalizePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/webhook"
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return path.Clean(value)
}

func splitRecipients(values ...string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			out = append(out, part)
		}
	}
	return out
}

func checkPath(name, webhookPath string) error {
	if webhookPath == "/health" {
		return fmt.Errorf("route %s: path /health is reserved", name)
	}
	if webhookPath == "/" || !strings.HasPrefix(webhookPath, "/") || strings.ContainsAny(webhookPath, "{} \t") {
		return fmt.Errorf("route %s: invalid path %q", name, webhookPath)
	}
	return nil
}

func loadConfig() (Config, error) {
	port := env("PORT", "8080")
	if _, err := strconv.Atoi(port); err != nil {
		return Config{}, fmt.Errorf("PORT must be a valid port number")
	}

	cfg := Config{
		Port:      port,
		SignalAPI: strings.TrimRight(env("SIGNAL_API", "http://signal-cli:8080"), "/"),
	}

	var err error
	if file := os.Getenv("ROUTES_FILE"); file != "" {
		cfg.Routes, err = loadRoutesFile(file)
	} else {
		cfg.Routes, err = legacyRoute()
	}
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func legacyRoute() ([]Route, error) {
	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	recipients := splitRecipients(os.Getenv("SIGNAL_RECIPIENT"))
	if secret == "" || len(recipients) == 0 {
		return nil, fmt.Errorf("missing GITHUB_WEBHOOK_SECRET or SIGNAL_RECIPIENT (or set ROUTES_FILE)")
	}
	route := Route{
		Name:       "github",
		Kind:       kindGitHub,
		Path:       normalizePath(env("WEBHOOK_PATH", "/webhook")),
		Secret:     secret,
		Recipients: recipients,
	}
	if err := checkPath(route.Name, route.Path); err != nil {
		return nil, err
	}
	return []Route{route}, nil
}

func loadRoutesFile(file string) ([]Route, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read routes file: %w", err)
	}
	return parseRoutes(data)
}

func parseRoutes(data []byte) ([]Route, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var file routeFile
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse routes: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse routes: extra data after JSON")
	}
	if len(file.Routes) == 0 {
		return nil, fmt.Errorf("routes file has no routes")
	}

	routes := make([]Route, 0, len(file.Routes))
	seen := make(map[string]string)
	for _, spec := range file.Routes {
		route, err := resolveRoute(spec)
		if err != nil {
			return nil, err
		}
		if other, ok := seen[route.Path]; ok {
			return nil, fmt.Errorf("routes %s and %s share path %s", other, route.Name, route.Path)
		}
		seen[route.Path] = route.Name
		routes = append(routes, route)
	}
	return routes, nil
}

func resolveRoute(spec routeSpec) (Route, error) {
	webhookPath := normalizePath(spec.Path)
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = webhookPath
	}
	if err := checkPath(name, webhookPath); err != nil {
		return Route{}, err
	}

	if spec.Secret != "" && spec.SecretEnv != "" {
		return Route{}, fmt.Errorf("route %s: set secret or secretEnv, not both", name)
	}
	secret := spec.Secret
	if spec.SecretEnv != "" {
		secret = os.Getenv(spec.SecretEnv)
		if secret == "" {
			return Route{}, fmt.Errorf("route %s: environment variable %s is empty", name, spec.SecretEnv)
		}
	}
	if secret == "" {
		return Route{}, fmt.Errorf("route %s: missing secret", name)
	}

	recipients := splitRecipients(spec.Recipients...)
	if spec.RecipientsEnv != "" {
		value := os.Getenv(spec.RecipientsEnv)
		if value == "" {
			return Route{}, fmt.Errorf("route %s: environment variable %s is empty", name, spec.RecipientsEnv)
		}
		recipients = splitRecipients(append(spec.Recipients, value)...)
	}
	if len(recipients) == 0 {
		recipients = splitRecipients(os.Getenv("SIGNAL_RECIPIENT"))
	}
	if len(recipients) == 0 {
		return Route{}, fmt.Errorf("route %s: missing recipients", name)
	}

	kind, err := routeKind(spec)
	if err != nil {
		return Route{}, fmt.Errorf("route %s: %w", name, err)
	}
	fields, err := cleanFields(spec.Fields)
	if err != nil {
		return Route{}, fmt.Errorf("route %s: %w", name, err)
	}

	route := Route{
		Name:       name,
		Kind:       kind,
		Path:       webhookPath,
		Secret:     secret,
		Recipients: recipients,
		Fields:     fields,
	}
	if kind != kindMap && len(spec.Match) > 0 {
		return Route{}, fmt.Errorf("route %s: kind %s does not use match", name, kind)
	}
	if kind == kindGitHub {
		if spec.Verify != "" || spec.Header != "" || spec.Prefix != "" || spec.Title != "" || len(fields) > 0 {
			return Route{}, fmt.Errorf("route %s: kind github does not use verify, header, prefix, title, or fields", name)
		}
		return route, nil
	}
	if (kind == kindAlert || kind == kindMap) && len(fields) > 0 {
		return Route{}, fmt.Errorf("route %s: kind %s does not use fields", name, kind)
	}
	if kind == kindMap {
		rules, err := cleanMatch(name, spec.Match)
		if err != nil {
			return Route{}, err
		}
		route.Match = rules
	}

	verify := strings.ToLower(strings.TrimSpace(spec.Verify))
	if verify == "" {
		if kind == kindAlert {
			verify = verifyToken
		} else {
			verify = verifyHMAC
		}
	}
	if verify != verifyHMAC && verify != verifyToken {
		return Route{}, fmt.Errorf("route %s: unknown verify %q", name, spec.Verify)
	}
	header := strings.TrimSpace(spec.Header)
	if header == "" {
		if verify == verifyToken {
			header = "Authorization"
		} else {
			header = "X-Signature-256"
		}
	}
	if strings.ContainsAny(header, "\r\n:") {
		return Route{}, fmt.Errorf("route %s: invalid header %q", name, header)
	}
	prefix := spec.Prefix
	if prefix == "" && strings.EqualFold(header, "Authorization") && verify == verifyToken {
		prefix = "Bearer "
	}
	title := strings.TrimSpace(spec.Title)
	if kind == kindGeneric && title == "" {
		title = name
	}
	route.Verify = verify
	route.Header = header
	route.Prefix = prefix
	route.Title = title
	return route, nil
}

func routeKind(spec routeSpec) (string, error) {
	kind := strings.ToLower(strings.TrimSpace(spec.Kind))
	if kind == "" {
		return kindGitHub, nil
	}
	switch kind {
	case kindGitHub, kindGeneric, kindMap:
		return kind, nil
	case kindAlert, "alertmanager", "grafana":
		return kindAlert, nil
	default:
		return "", fmt.Errorf("unknown kind %q", spec.Kind)
	}
}

func cleanMatch(routeName string, specs []mapRuleSpec) ([]mapRule, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("route %s: kind map requires match", routeName)
	}
	rules := make([]mapRule, 0, len(specs))
	for i, spec := range specs {
		rule, err := cleanMapRule(routeName, i, spec)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func cleanMapRule(routeName string, index int, spec mapRuleSpec) (mapRule, error) {
	fail := func(format string, args ...any) (mapRule, error) {
		return mapRule{}, fmt.Errorf("route %s: match %d: %s", routeName, index+1, fmt.Sprintf(format, args...))
	}
	when := make(map[string]string, len(spec.When))
	for path, want := range spec.When {
		if err := validPath(path); err != nil {
			return fail("%s", err.Error())
		}
		want = strings.TrimSpace(want)
		if want == "" {
			return fail("empty when value for %s", path)
		}
		when[path] = want
	}
	var present []string
	for _, path := range spec.Present {
		path = strings.TrimSpace(path)
		if err := validPath(path); err != nil {
			return fail("%s", err.Error())
		}
		present = append(present, path)
	}
	var ignore []string
	for _, value := range spec.Ignore {
		value = strings.TrimSpace(value)
		if value == "" {
			return fail("empty ignore value")
		}
		ignore = append(ignore, value)
	}
	status := strings.TrimSpace(spec.Status)
	if len(ignore) > 0 && status == "" {
		return fail("ignore requires status")
	}
	if len(spec.StatusMap) > 0 && status == "" {
		return fail("statusMap requires status")
	}
	statusMap := make(map[string]string, len(spec.StatusMap))
	for key, value := range spec.StatusMap {
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return fail("empty statusMap entry")
		}
		statusMap[key] = value
	}
	if len(statusMap) == 0 {
		statusMap = nil
	}
	if err := optionalPath(status); err != nil {
		return fail("%s", err.Error())
	}
	for _, path := range []string{spec.Subject, spec.Summary, spec.Link} {
		if err := optionalPath(path); err != nil {
			return fail("%s", err.Error())
		}
	}
	fields := make([]mapField, 0, len(spec.Fields))
	for _, field := range spec.Fields {
		path := strings.TrimSpace(field.Path)
		if err := validPath(path); err != nil {
			return fail("%s", err.Error())
		}
		label := strings.TrimSpace(field.Label)
		if label == "" {
			label = path
		}
		fields = append(fields, mapField{Label: label, Path: path, TrimPrefix: field.TrimPrefix})
	}
	var each *mapEach
	if spec.Each != nil {
		if err := validPath(strings.TrimSpace(spec.Each.Path)); err != nil {
			return fail("each %s", err.Error())
		}
		text := strings.TrimSpace(spec.Each.Text)
		detail := strings.TrimSpace(spec.Each.Detail)
		if text == "" && detail == "" {
			return fail("each requires text or detail")
		}
		if text != "" {
			if err := validPath(text); err != nil {
				return fail("each %s", err.Error())
			}
		}
		if detail != "" {
			if err := validPath(detail); err != nil {
				return fail("each %s", err.Error())
			}
		}
		limit := spec.Each.Limit
		if limit == 0 {
			limit = 5
		}
		if limit < 1 || limit > 20 {
			return fail("each limit must be from 1 to 20")
		}
		if spec.Each.Short < 0 || spec.Each.Short > 64 {
			return fail("each short must be from 1 to 64")
		}
		each = &mapEach{
			Path:   strings.TrimSpace(spec.Each.Path),
			Text:   text,
			Detail: detail,
			Limit:  limit,
			Short:  spec.Each.Short,
		}
	}
	rule := mapRule{
		When:      when,
		Present:   present,
		Ignore:    ignore,
		Status:    status,
		StatusMap: statusMap,
		Title:     strings.TrimSpace(spec.Title),
		Subject:   strings.TrimSpace(spec.Subject),
		Summary:   strings.TrimSpace(spec.Summary),
		Fields:    fields,
		Each:      each,
		Link:      strings.TrimSpace(spec.Link),
	}
	if rule.Title == "" && rule.Status == "" && rule.Subject == "" && rule.Summary == "" && len(rule.Fields) == 0 && rule.Each == nil && rule.Link == "" {
		return fail("rule has nothing to send")
	}
	return rule, nil
}

func optionalPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	return validPath(path)
}

func validPath(path string) error {
	if path == "" || strings.Contains(path, "..") || strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".") || strings.ContainsAny(path, " \t{}") {
		return fmt.Errorf("invalid path %q", path)
	}
	return nil
}

func cleanFields(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" || strings.Contains(field, "..") || strings.HasPrefix(field, ".") || strings.HasSuffix(field, ".") || strings.ContainsAny(field, " \t") {
			return nil, fmt.Errorf("invalid field %q", field)
		}
		out = append(out, field)
	}
	return out, nil
}

func verifySignature(secret string, body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil || len(provided) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)

	return hmac.Equal(provided, mac.Sum(nil))
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSuffix(line, "\r")
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

func shortSHA(id string) string {
	if len(id) > 7 {
		return id[:7]
	}
	if id == "" {
		return "unknown"
	}
	return id
}

func repoName(r repository) string {
	if r.FullName == "" {
		return "unknown repository"
	}
	return r.FullName
}

func actorName(a ...actor) string {
	for _, person := range a {
		if person.Name != "" {
			return person.Name
		}
		if person.Login != "" {
			return person.Login
		}
	}
	return "unknown"
}

func orEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func prettyAction(action string) string {
	return strings.ReplaceAll(action, "_", " ")
}

// utf16Len is the length in UTF-16 code units. signal-cli text styles use that
// unit, so emoji (which sit outside the BMP) count as two.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// signalText is a Signal message plus text-style ranges (start:length:STYLE).
type signalText struct {
	body   string
	styles []string
}

type textBuilder struct {
	b      strings.Builder
	styles []string
	off    int
}

func (w *textBuilder) write(s string) {
	if s == "" {
		return
	}
	w.b.WriteString(s)
	w.off += utf16Len(s)
}

func (w *textBuilder) style(s, style string) {
	if s == "" {
		return
	}
	start := w.off
	w.write(s)
	w.styles = append(w.styles, fmt.Sprintf("%d:%d:%s", start, w.off-start, style))
}

func (w *textBuilder) bold(s string)   { w.style(s, "BOLD") }
func (w *textBuilder) italic(s string) { w.style(s, "ITALIC") }
func (w *textBuilder) mono(s string)   { w.style(s, "MONOSPACE") }
func (w *textBuilder) strike(s string) { w.style(s, "STRIKETHROUGH") }
func (w *textBuilder) nl()             { w.write("\n") }

func (w *textBuilder) header(emoji, title, subject string) {
	if emoji != "" {
		w.write(emoji)
		w.write(" ")
	}
	w.bold(title)
	if subject != "" {
		w.write(" · ")
		w.bold(subject)
	}
	w.nl()
}

func (w *textBuilder) field(label, value string) {
	w.bold(label)
	w.write(": ")
	w.write(value)
	w.nl()
}

func (w *textBuilder) prose(s string, strike bool) {
	if strike {
		w.strike(s)
		return
	}
	w.italic(s)
}

func (w *textBuilder) link(urls ...string) {
	for _, u := range urls {
		if u == "" {
			continue
		}
		if !strings.HasSuffix(w.b.String(), "\n") {
			w.nl()
		}
		w.nl()
		w.write(u)
		return
	}
}

func (w *textBuilder) done() signalText {
	return signalText{
		body:   strings.TrimRight(w.b.String(), "\n"),
		styles: w.styles,
	}
}

func outcomeEmoji(outcome string) string {
	switch outcome {
	case "success", "built":
		return "✅"
	case "failure", "failed", "error", "errored":
		return "❌"
	case "cancelled", "canceled":
		return "🚫"
	case "timed_out":
		return "⏱️"
	case "skipped":
		return "⏭️"
	case "neutral":
		return "⚪"
	case "action_required", "stale":
		return "⚠️"
	default:
		return "⚙️"
	}
}

func prEmoji(action string) string {
	switch action {
	case "merged":
		return "🎉"
	case "opened":
		return "🔀"
	case "reopened":
		return "🔁"
	case "closed":
		return "🚫"
	case "ready_for_review":
		return "👀"
	case "converted_to_draft":
		return "📝"
	default:
		return "🔀"
	}
}

func issueEmoji(action string) string {
	switch action {
	case "opened":
		return "🐛"
	case "reopened":
		return "🔁"
	case "closed":
		return "✅"
	default:
		return "🐛"
	}
}

func buildPushMessage(p pushPayload) signalText {
	refLabel := "Branch"
	ref := strings.TrimPrefix(p.Ref, "refs/heads/")
	emoji := "📤"
	title := "Push"
	if strings.HasPrefix(p.Ref, "refs/tags/") {
		ref = strings.TrimPrefix(p.Ref, "refs/tags/")
		refLabel = "Tag"
		emoji = "🏷️"
		title = "Tag push"
	} else if ref == "" {
		ref = "unknown"
	}

	var w textBuilder
	w.header(emoji, title, repoName(p.Repository))
	w.field(refLabel, ref)
	w.field("By", actorName(p.Pusher, p.Sender))
	w.field("Commits", strconv.Itoa(len(p.Commits)))

	shown := 0
	for _, commit := range p.Commits {
		if shown >= 5 {
			break
		}
		if shown == 0 {
			w.nl()
		}
		shown++
		w.write("• ")
		w.mono(shortSHA(commit.ID))
		w.write(" ")
		w.italic(truncate(firstLine(commit.Message), 150))
		w.nl()
	}
	if len(p.Commits) > shown {
		w.italic(fmt.Sprintf("… and %d more", len(p.Commits)-shown))
		w.nl()
	}

	w.link(p.Compare)
	return w.done()
}

func buildWorkflowRunMessage(p workflowRunPayload) (signalText, bool) {
	if p.Action != "completed" {
		return signalText{}, false
	}

	run := p.WorkflowRun
	title := orEmpty(run.DisplayTitle, run.Name)
	conclusion := orEmpty(run.Conclusion, "unknown")

	var w textBuilder
	w.header(outcomeEmoji(conclusion), "CI", repoName(p.Repository))
	w.field("Workflow", orEmpty(run.Name, "unknown"))
	w.field("Conclusion", conclusion)
	w.field("Branch", orEmpty(run.HeadBranch, "unknown"))
	w.field("By", actorName(run.Actor, p.Sender))
	if title != "" && title != run.Name {
		w.bold("Title")
		w.write(": ")
		w.italic(truncate(title, 150))
		w.nl()
	}
	w.link(run.HTMLURL)
	return w.done(), true
}

func buildCheckRunMessage(p checkRunPayload) (signalText, bool) {
	if p.Action != "completed" {
		return signalText{}, false
	}

	run := p.CheckRun
	conclusion := orEmpty(run.Conclusion, "unknown")

	var w textBuilder
	w.header(outcomeEmoji(conclusion), "Check", repoName(p.Repository))
	w.field("Check", orEmpty(run.Name, "unknown"))
	w.field("Conclusion", conclusion)
	w.field("Branch", orEmpty(run.CheckSuite.HeadBranch, "unknown"))
	w.bold("Commit")
	w.write(": ")
	w.mono(shortSHA(run.HeadSHA))
	w.nl()
	w.field("By", actorName(p.Sender))
	w.link(run.HTMLURL)
	return w.done(), true
}

func buildPageBuildMessage(p pageBuildPayload) (signalText, bool) {
	status := p.Build.Status
	if status != "built" && status != "errored" {
		return signalText{}, false
	}

	var w textBuilder
	w.header(outcomeEmoji(status), "Pages", repoName(p.Repository))
	w.field("Status", status)
	w.bold("Commit")
	w.write(": ")
	w.mono(shortSHA(p.Build.Commit))
	w.nl()
	w.field("By", actorName(p.Build.Pusher, p.Sender))
	if status == "errored" && p.Build.Error.Message != "" {
		w.bold("Error")
		w.write(": ")
		w.italic(truncate(firstLine(p.Build.Error.Message), 200))
		w.nl()
	}
	w.link(p.Repository.HTMLURL)
	return w.done(), true
}

func buildDeploymentStatusMessage(p deploymentStatusPayload) (signalText, bool) {
	state := p.DeploymentStatus.State
	switch state {
	case "success", "failure", "error":
	default:
		return signalText{}, false
	}

	envName := p.DeploymentStatus.Environment
	if envName == "" {
		envName = p.Deployment.Environment
	}

	emoji := outcomeEmoji(state)
	if state == "success" {
		emoji = "🚀"
	}

	var w textBuilder
	w.header(emoji, "Deploy", repoName(p.Repository))
	w.field("Environment", orEmpty(envName, "unknown"))
	w.field("State", state)
	w.bold("Ref")
	w.write(": ")
	w.mono(orEmpty(p.Deployment.Ref, shortSHA(p.Deployment.SHA)))
	w.nl()
	w.field("By", actorName(p.Sender))
	desc := p.DeploymentStatus.Description
	if desc == "" {
		desc = p.Deployment.Description
	}
	if desc != "" {
		w.italic(truncate(firstLine(desc), 200))
		w.nl()
	}
	w.link(p.DeploymentStatus.LogURL, p.DeploymentStatus.TargetURL, p.Repository.HTMLURL)
	return w.done(), true
}

func buildPullRequestMessage(p pullRequestPayload) (signalText, bool) {
	action := p.Action
	switch action {
	case "opened", "reopened", "closed", "ready_for_review", "converted_to_draft":
	default:
		return signalText{}, false
	}

	if action == "closed" && p.PullRequest.Merged {
		action = "merged"
	}

	pr := p.PullRequest
	var w textBuilder
	w.header(prEmoji(action), "PR", repoName(p.Repository))
	w.write("#")
	w.bold(strconv.Itoa(p.Number))
	w.write(" ")
	w.bold(prettyAction(action))
	w.write(": ")
	w.prose(truncate(orEmpty(pr.Title, "untitled"), 150), action == "closed")
	w.nl()
	w.mono(orEmpty(pr.Head.Ref, "?"))
	w.write(" → ")
	w.mono(orEmpty(pr.Base.Ref, "?"))
	w.nl()
	w.field("By", actorName(pr.User, p.Sender))
	w.link(pr.HTMLURL)
	return w.done(), true
}

func buildReleaseMessage(p releasePayload) (signalText, bool) {
	switch p.Action {
	case "published", "released":
	default:
		return signalText{}, false
	}

	rel := p.Release
	kind := "Release"
	emoji := "🏷️"
	if rel.Prerelease {
		kind = "Prerelease"
		emoji = "🧪"
	}
	name := rel.Name
	if name == "" || name == rel.TagName {
		name = rel.TagName
	}

	var w textBuilder
	w.header(emoji, kind, repoName(p.Repository))
	w.bold(orEmpty(rel.TagName, "unknown"))
	if name != "" && name != rel.TagName {
		w.write(" ")
		w.italic("(" + name + ")")
	}
	w.nl()
	w.field("By", actorName(rel.Author, p.Sender))
	w.link(rel.HTMLURL)
	return w.done(), true
}

func buildIssuesMessage(p issuesPayload) (signalText, bool) {
	switch p.Action {
	case "opened", "reopened", "closed":
	default:
		return signalText{}, false
	}

	issue := p.Issue
	var w textBuilder
	w.header(issueEmoji(p.Action), "Issue", repoName(p.Repository))
	w.write("#")
	w.bold(strconv.Itoa(issue.Number))
	w.write(" ")
	w.bold(p.Action)
	w.write(": ")
	w.prose(truncate(orEmpty(issue.Title, "untitled"), 150), p.Action == "closed")
	w.nl()
	w.field("By", actorName(issue.User, p.Sender))
	w.link(issue.HTMLURL)
	return w.done(), true
}

func buildCreateDeleteMessage(event string, p createDeletePayload) signalText {
	emoji := "🌿"
	title := "Created"
	if event == "delete" {
		emoji = "🗑️"
		title = "Deleted"
	} else if p.RefType == "tag" {
		emoji = "🏷️"
	}

	var w textBuilder
	w.header(emoji, title, repoName(p.Repository))
	w.write(orEmpty(p.RefType, "ref"))
	w.write(" ")
	w.mono(orEmpty(p.Ref, "unknown"))
	w.nl()
	w.field("By", actorName(p.Sender))
	w.link(p.Repository.HTMLURL)
	return w.done()
}

func buildStarMessage(p starPayload) (signalText, bool) {
	if p.Action != "created" {
		return signalText{}, false
	}
	var w textBuilder
	w.header("⭐", "Star", repoName(p.Repository))
	w.field("By", actorName(p.Sender))
	w.link(p.Repository.HTMLURL)
	return w.done(), true
}

func buildForkMessage(p forkPayload) signalText {
	var w textBuilder
	w.header("🍴", "Fork", repoName(p.Repository))
	w.field("To", orEmpty(p.Forkee.FullName, "unknown"))
	w.field("By", actorName(p.Sender))
	w.link(p.Forkee.HTMLURL, p.Repository.HTMLURL)
	return w.done()
}

// buildMessage returns a Signal notification and whether one should be sent.
func buildMessage(event string, body []byte) (signalText, bool, error) {
	switch event {
	case "ping":
		return signalText{}, false, nil

	case "push":
		var p pushPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		return buildPushMessage(p), true, nil

	case "workflow_run":
		var p workflowRunPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildWorkflowRunMessage(p)
		return msg, ok, nil

	case "check_run":
		var p checkRunPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildCheckRunMessage(p)
		return msg, ok, nil

	case "page_build":
		var p pageBuildPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildPageBuildMessage(p)
		return msg, ok, nil

	case "deployment_status":
		var p deploymentStatusPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildDeploymentStatusMessage(p)
		return msg, ok, nil

	case "pull_request":
		var p pullRequestPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildPullRequestMessage(p)
		return msg, ok, nil

	case "release":
		var p releasePayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildReleaseMessage(p)
		return msg, ok, nil

	case "issues":
		var p issuesPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildIssuesMessage(p)
		return msg, ok, nil

	case "create", "delete":
		var p createDeletePayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		return buildCreateDeleteMessage(event, p), true, nil

	case "star":
		var p starPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildStarMessage(p)
		return msg, ok, nil

	case "fork":
		var p forkPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		return buildForkMessage(p), true, nil

	default:
		return signalText{}, false, nil
	}
}

func sendSignal(ctx context.Context, client *http.Client, api, recipient string, message signalText) error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Errorf("generate request ID: %w", err)
	}

	params := map[string]any{
		"recipient": []string{recipient},
		"message":   message.body,
	}
	if len(message.styles) > 0 {
		params["textStyle"] = message.styles
	}

	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "send",
		"params":  params,
		"id":      hex.EncodeToString(id[:]),
	})
	if err != nil {
		return fmt.Errorf("encode RPC request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, api+"/api/v1/rpc",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Signal API request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read Signal API response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Signal API HTTP %d: %s", resp.StatusCode, responseBody)
	}

	var rpc RPCResponse
	if err := json.Unmarshal(responseBody, &rpc); err != nil {
		return fmt.Errorf("invalid Signal API JSON: %w", err)
	}

	if len(rpc.Error) > 0 && string(rpc.Error) != "null" {
		return fmt.Errorf("Signal JSON-RPC error: %s", rpc.Error)
	}

	return nil
}

// deliver notifies each recipient on its own. GitHub retries the whole
// delivery on a non-2xx response, so a later failure must not duplicate a
// send that already succeeded.
func deliver(api string, recipients []string, message signalText) (int, []deliveryFailure) {
	ctx, cancel := context.WithTimeout(context.Background(), deliveryBudget)
	defer cancel()
	client := &http.Client{Timeout: deliveryBudget}

	var mu sync.Mutex
	sent := 0
	var failures []deliveryFailure
	var wg sync.WaitGroup
	for _, recipient := range recipients {
		wg.Add(1)
		go func(recipient string) {
			defer wg.Done()
			err := sendSignal(ctx, client, api, recipient, message)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, deliveryFailure{recipient: recipient, err: err})
				return
			}
			sent++
		}(recipient)
	}
	wg.Wait()
	return sent, failures
}

func verifyGeneric(route Route, headerValue string, body []byte) bool {
	switch route.Verify {
	case verifyHMAC:
		return verifySignature(route.Secret, body, headerValue)
	case verifyToken:
		got := headerValue
		if route.Prefix != "" {
			rest, ok := strings.CutPrefix(headerValue, route.Prefix)
			if !ok {
				return false
			}
			got = rest
		}
		return hmac.Equal([]byte(got), []byte(route.Secret))
	default:
		return false
	}
}

func buildGenericMessage(route Route, body []byte) (signalText, error) {
	var w textBuilder
	w.header("🔔", route.Title, "")
	if len(route.Fields) == 0 {
		if text := genericBody(body); text != "" {
			w.nl()
			w.write(truncate(text, 400))
		}
		return w.done(), nil
	}

	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return signalText{}, err
	}
	var linkURL string
	for _, field := range route.Fields {
		shown := "unknown"
		if value, ok := lookupJSON(doc, field); ok {
			shown = truncate(value, 200)
		}
		w.field(field, shown)
		if linkURL == "" && (strings.HasPrefix(shown, "https://") || strings.HasPrefix(shown, "http://")) {
			linkURL = shown
		}
	}
	if linkURL != "" {
		w.link(linkURL)
	}
	return w.done(), nil
}

func genericBody(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return ""
	}
	var compacted bytes.Buffer
	if json.Compact(&compacted, body) == nil {
		return compacted.String()
	}
	return string(body)
}

func buildMapMessage(route Route, body []byte) (signalText, bool, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return signalText{}, false, err
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return signalText{}, false, fmt.Errorf("expected JSON object")
	}
	for _, rule := range route.Match {
		if !mapRuleMatches(root, rule) {
			continue
		}
		if mapIgnored(root, rule) {
			return signalText{}, false, nil
		}
		return renderMapRule(route, root, rule), true, nil
	}
	return signalText{}, false, nil
}

func mapRuleMatches(root map[string]any, rule mapRule) bool {
	for path, want := range rule.When {
		got, ok := lookupJSON(root, path)
		if !ok || !strings.EqualFold(got, want) {
			return false
		}
	}
	for _, path := range rule.Present {
		got, ok := lookupValue(root, path)
		if !ok || !valuePresent(got) {
			return false
		}
	}
	return true
}

func valuePresent(v any) bool {
	switch n := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(n) != ""
	case []any:
		return len(n) > 0
	case map[string]any:
		return len(n) > 0
	default:
		return true
	}
}

func mapIgnored(root map[string]any, rule mapRule) bool {
	if rule.Status == "" || len(rule.Ignore) == 0 {
		return false
	}
	got, ok := ruleStatus(root, rule)
	if !ok {
		return false
	}
	for _, skip := range rule.Ignore {
		if strings.EqualFold(got, skip) {
			return true
		}
	}
	return false
}

func ruleStatus(root map[string]any, rule mapRule) (string, bool) {
	got, ok := lookupJSON(root, rule.Status)
	if !ok {
		return "", false
	}
	if mapped, ok := rule.StatusMap[strings.ToLower(got)]; ok {
		return mapped, true
	}
	return got, true
}

func renderMapRule(route Route, root map[string]any, rule mapRule) signalText {
	emoji := "🔔"
	title := rule.Title
	if title == "" {
		title = route.Title
	}
	statusValue := ""
	strike := false
	if rule.Status != "" {
		if got, ok := ruleStatus(root, rule); ok {
			statusValue = got
			var word string
			emoji, word, strike = mapStatus(got)
			if title == "" {
				title = word
			}
		}
	}
	if title == "" {
		title = "Notice"
	}
	subject := ""
	if rule.Subject != "" {
		subject, _ = lookupJSON(root, rule.Subject)
	}

	var w textBuilder
	w.header(emoji, title, subject)
	if statusValue != "" && (rule.Title != "" || route.Title != "") {
		w.field("Status", statusValue)
	}
	if rule.Summary != "" {
		if summary, ok := lookupJSON(root, rule.Summary); ok && summary != "" {
			w.prose(truncate(firstLine(summary), 200), strike)
			w.nl()
		}
	}
	for _, field := range rule.Fields {
		value, ok := lookupJSON(root, field.Path)
		if !ok || value == "" {
			continue
		}
		if field.TrimPrefix != "" {
			value = strings.TrimPrefix(value, field.TrimPrefix)
		}
		w.field(field.Label, truncate(value, 200))
	}
	if rule.Each != nil {
		renderMapEach(&w, root, rule.Each)
	}
	if rule.Link != "" {
		if link, ok := lookupJSON(root, rule.Link); ok {
			w.link(link)
		}
	}
	return w.done()
}

func renderMapEach(w *textBuilder, root map[string]any, each *mapEach) {
	raw, ok := lookupValue(root, each.Path)
	if !ok {
		return
	}
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return
	}
	shown := 0
	extra := 0
	for i, item := range items {
		if shown == each.Limit {
			extra = len(items) - i
			break
		}
		elem, ok := item.(map[string]any)
		if !ok {
			continue
		}
		text := ""
		if each.Text != "" {
			text, _ = lookupJSON(elem, each.Text)
			if each.Short > 0 {
				text = truncate(text, each.Short)
			}
		}
		detail := ""
		if each.Detail != "" {
			detail, _ = lookupJSON(elem, each.Detail)
			detail = truncate(firstLine(detail), 150)
		}
		if text == "" && detail == "" {
			continue
		}
		if shown == 0 {
			w.nl()
		}
		shown++
		w.write("• ")
		if text != "" {
			w.mono(text)
		}
		if detail != "" {
			if text != "" {
				w.write(" ")
			}
			w.italic(detail)
		}
		w.nl()
	}
	if extra > 0 {
		w.italic(fmt.Sprintf("… and %d more", extra))
		w.nl()
	}
}

func mapStatus(status string) (emoji, word string, strike bool) {
	switch strings.ToLower(status) {
	case "success", "successful", "passed":
		return "✅", "Success", false
	case "failure", "failed", "error", "errored":
		return "❌", "Failed", false
	case "down":
		return "❌", "Down", false
	case "up":
		return "✅", "Up", true
	case "new":
		return "🆕", "New", false
	case "update", "updated":
		return "⬆️", "Update", false
	case "killed":
		return "❌", "Killed", false
	case "firing", "alerting":
		return "🔥", "Firing", false
	case "resolved", "ok":
		return "✅", "Resolved", true
	case "closed":
		return "🚫", "Closed", true
	case "merged":
		return "🎉", "Merged", false
	case "pending":
		return "⏳", "Pending", false
	case "running":
		return "⚙️", "Running", false
	case "cancelled", "canceled":
		return "🚫", "Canceled", false
	case "skipped":
		return "⏭️", "Skipped", false
	default:
		if status == "" {
			return "🔔", "Notice", false
		}
		return "🔔", prettyAction(status), false
	}
}

func lookupJSON(v any, path string) (string, bool) {
	found, ok := lookupValue(v, path)
	if !ok {
		return "", false
	}
	return formatJSON(found), true
}

func lookupValue(v any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	cur := v
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[part]
		if !ok || cur == nil {
			return nil, false
		}
	}
	return cur, true
}

func formatJSON(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case float64:
		if !math.IsInf(n, 0) && n >= math.MinInt64 && n <= math.MaxInt64 && n == math.Trunc(n) {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(n)
	default:
		encoded, err := json.Marshal(n)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}

type alertPayload struct {
	Status            string            `json:"status"`
	State             string            `json:"state"`
	Title             string            `json:"title"`
	Message           string            `json:"message"`
	ExternalURL       string            `json:"externalURL"`
	TruncatedAlerts   int               `json:"truncatedAlerts"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	Alerts            []alertItem       `json:"alerts"`
	RuleName          string            `json:"ruleName"`
	RuleURL           string            `json:"ruleUrl"`
	EvalMatches       []grafanaMatch    `json:"evalMatches"`
}

type alertItem struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	GeneratorURL string            `json:"generatorURL"`
	DashboardURL string            `json:"dashboardURL"`
	PanelURL     string            `json:"panelURL"`
	ValueString  string            `json:"valueString"`
	Fingerprint  string            `json:"fingerprint"`
}

type grafanaMatch struct {
	Value  any    `json:"value"`
	Metric string `json:"metric"`
}

func buildAlertMessage(route Route, body []byte) (signalText, error) {
	var p alertPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return signalText{}, err
	}
	if len(p.Alerts) == 0 && len(p.EvalMatches) == 0 && p.RuleName == "" && p.Status == "" && p.State == "" && p.Title == "" {
		return signalText{}, fmt.Errorf("unrecognized alert payload")
	}

	status := alertStatus(p)
	emoji, title := alertPresentation(status)
	name := alertName(p)
	if name == "" {
		name = route.Title
	}
	summary := alertSummary(p)
	resolved := canonAlertStatus(status) == "resolved"

	var w textBuilder
	w.header(emoji, title, name)
	if severity := labelValue(p.CommonLabels, p.Alerts, "severity"); severity != "" {
		w.field("Severity", severity)
	}
	total := len(p.Alerts) + p.TruncatedAlerts
	if total > 1 {
		w.field("Alerts", strconv.Itoa(total))
	}
	if summary != "" {
		w.prose(truncate(summary, 200), resolved)
		w.nl()
	}

	shown := 0
	for _, item := range p.Alerts {
		if shown == maxShownAlerts {
			break
		}
		if shown == 0 {
			w.nl()
		}
		shown++
		writeAlertBullet(&w, status, name, summary, item)
	}
	if shown == 0 {
		for _, match := range p.EvalMatches {
			if shown == maxShownAlerts {
				break
			}
			if shown == 0 {
				w.nl()
			}
			shown++
			w.write("• ")
			if match.Metric != "" {
				w.mono(match.Metric)
				w.write(" ")
			}
			w.write(formatJSON(match.Value))
			w.nl()
		}
	}
	extra := len(p.Alerts) - shown + p.TruncatedAlerts
	if extra < 0 {
		extra = len(p.EvalMatches) - shown
	}
	if extra > 0 {
		w.italic(fmt.Sprintf("… and %d more", extra))
		w.nl()
	}
	w.link(alertLink(p))
	return w.done(), nil
}

const maxShownAlerts = 5

var alertLabelKeys = []string{
	"instance", "pod", "container", "job", "namespace", "service",
	"node", "device", "mountpoint", "endpoint", "persistentvolumeclaim",
}

func alertStatus(p alertPayload) string {
	if s := strings.TrimSpace(p.Status); s != "" {
		return s
	}
	if s := strings.TrimSpace(p.State); s != "" {
		return s
	}
	if len(p.Alerts) > 0 {
		return p.Alerts[0].Status
	}
	return ""
}

func canonAlertStatus(status string) string {
	switch strings.ToLower(status) {
	case "firing", "alerting":
		return "firing"
	case "resolved", "ok":
		return "resolved"
	default:
		return strings.ToLower(status)
	}
}

func alertPresentation(status string) (string, string) {
	switch canonAlertStatus(status) {
	case "firing":
		return "🔥", "Firing"
	case "resolved":
		return "✅", "Resolved"
	case "pending":
		return "⏳", "Pending"
	case "no_data":
		return "❓", "No data"
	case "paused":
		return "⏸️", "Paused"
	default:
		if status == "" {
			return "🔔", "Alert"
		}
		return "🔔", prettyAction(status)
	}
}

func alertName(p alertPayload) string {
	if name := labelValue(p.CommonLabels, nil, "alertname"); name != "" {
		return name
	}
	if name := p.GroupLabels["alertname"]; name != "" {
		return name
	}
	if len(p.Alerts) > 0 {
		if name := p.Alerts[0].Labels["alertname"]; name != "" {
			return name
		}
	}
	if p.RuleName != "" {
		return p.RuleName
	}
	if p.Title != "" && !strings.HasPrefix(strings.TrimSpace(p.Title), "[") {
		return p.Title
	}
	return ""
}

func alertSummary(p alertPayload) string {
	if text := annotationText(p.CommonAnnotations); text != "" {
		return text
	}
	if len(p.Alerts) > 0 {
		if text := annotationText(p.Alerts[0].Annotations); text != "" {
			return text
		}
	}
	return firstLine(p.Message)
}

func annotationText(m map[string]string) string {
	if text := firstLine(m["summary"]); text != "" {
		return text
	}
	return firstLine(m["description"])
}

func labelValue(common map[string]string, alerts []alertItem, key string) string {
	if v := common[key]; v != "" {
		return v
	}
	if len(alerts) > 0 {
		return alerts[0].Labels[key]
	}
	return ""
}

func writeAlertBullet(w *textBuilder, groupStatus, groupName, groupSummary string, item alertItem) {
	w.write("• ")
	if itemStatus := strings.TrimSpace(item.Status); itemStatus != "" && canonAlertStatus(itemStatus) != canonAlertStatus(groupStatus) {
		w.write(itemStatus)
		w.write(" ")
	}
	target := alertTarget(item.Labels, groupName)
	if target == "" && item.Fingerprint != "" {
		target = shortSHA(item.Fingerprint)
	}
	if target != "" {
		w.mono(target)
	}
	detail := annotationText(item.Annotations)
	if detail == groupSummary {
		detail = ""
	}
	if detail == "" {
		detail = firstLine(item.ValueString)
	}
	if detail != "" {
		if target != "" {
			w.nl()
			w.write("  ")
		} else {
			w.write(" ")
		}
		w.italic(truncate(detail, 150))
	}
	w.nl()
}

func alertTarget(labels map[string]string, groupName string) string {
	var parts []string
	for _, key := range alertLabelKeys {
		if v := labels[key]; v != "" {
			parts = append(parts, v)
			if len(parts) == 2 {
				break
			}
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	if name := labels["alertname"]; name != "" && name != groupName {
		return name
	}
	return ""
}

func alertLink(p alertPayload) string {
	for _, item := range p.Alerts {
		if item.PanelURL != "" {
			return item.PanelURL
		}
	}
	for _, item := range p.Alerts {
		if item.DashboardURL != "" {
			return item.DashboardURL
		}
	}
	for _, item := range p.Alerts {
		if item.GeneratorURL != "" {
			return item.GeneratorURL
		}
	}
	if p.RuleURL != "" {
		return p.RuleURL
	}
	return p.ExternalURL
}

func webhook(api string, route Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if route.Kind != kindGeneric && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "Expected application/json", http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
		if err != nil {
			http.Error(w, "Invalid or oversized request body", http.StatusBadRequest)
			return
		}

		var (
			message signalText
			notify  bool
			event   string
		)
		if route.Kind == kindGeneric || route.Kind == kindAlert || route.Kind == kindMap {
			if !verifyGeneric(route, r.Header.Get(route.Header), body) {
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}
			switch route.Kind {
			case kindAlert:
				message, err = buildAlertMessage(route, body)
				notify = true
			case kindMap:
				message, notify, err = buildMapMessage(route, body)
			default:
				message, err = buildGenericMessage(route, body)
				notify = true
			}
			event = route.Name
		} else {
			if !verifySignature(route.Secret, body, r.Header.Get("X-Hub-Signature-256")) {
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}
			event = r.Header.Get("X-GitHub-Event")
			message, notify, err = buildMessage(event, body)
		}
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if !notify {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Event ignored"))
			return
		}

		sent, failures := deliver(api, route.Recipients, message)
		for _, failure := range failures {
			log.Printf("Signal delivery failed for %s to %s: %v", event, failure.recipient, failure.err)
		}
		if sent == 0 {
			http.Error(w, "Signal delivery failed", http.StatusBadGateway)
			return
		}
		if len(failures) > 0 {
			log.Printf("Signal notification partially sent for %s (%d/%d)", event, sent, len(route.Recipients))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Notification partially sent"))
			return
		}

		log.Printf("Signal notification sent for %s", event)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Notification sent"))
	}
}

func newMux(cfg Config) http.Handler {
	mux := http.NewServeMux()
	for _, route := range cfg.Routes {
		mux.HandleFunc(route.Path, webhook(cfg.SignalAPI, route))
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on port %s", cfg.Port)
	for _, route := range cfg.Routes {
		log.Printf("webhook %s (%s) on %s for %d recipient(s)", route.Name, route.Kind, route.Path, len(route.Recipients))
	}

	server := &http.Server{
		Addr:              "0.0.0.0:" + cfg.Port,
		Handler:           newMux(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
