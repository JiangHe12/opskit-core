package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		want       string
		mustNotSee []string
	}{
		{
			name:  "private key",
			input: "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-body\n-----END OPENSSH PRIVATE KEY-----\nafter",
			want:  "before\n[REDACTED PRIVATE KEY]\nafter",
			mustNotSee: []string{
				"secret-body",
				"BEGIN OPENSSH PRIVATE KEY",
			},
		},
		{
			name:       "aws access key",
			input:      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			want:       "AWS_ACCESS_KEY_ID=[REDACTED]",
			mustNotSee: []string{"AKIAIOSFODNN7EXAMPLE"},
		},
		{
			name:       "jwt",
			input:      "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_-",
			want:       "authorization: Bearer [REDACTED]",
			mustNotSee: []string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "signature_-"},
		},
		{
			name:       "password assignment",
			input:      "password=hunter2",
			want:       "password=[REDACTED]",
			mustNotSee: []string{"hunter2"},
		},
		{
			name:       "token quoted assignment",
			input:      `token = "abc def"`,
			want:       "token = [REDACTED]",
			mustNotSee: []string{"abc def"},
		},
		{
			name:       "secret single quoted assignment",
			input:      "client_secret='top-secret'",
			want:       "client_secret=[REDACTED]",
			mustNotSee: []string{"top-secret"},
		},
		{
			name:  "non sensitive output",
			input: "status=healthy\nusers=12\nlatency=4ms",
			want:  "status=healthy\nusers=12\nlatency=4ms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := String(tt.input)
			if got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
			for _, secret := range tt.mustNotSee {
				if strings.Contains(got, secret) {
					t.Errorf("String() leaked %q in %q", secret, got)
				}
			}
		})
	}
}

func TestStringAdversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		mustNotSee []string
	}{
		{
			name:  "generic pem private key crlf",
			input: "-----BEGIN PRIVATE KEY-----\r\nvery-secret\r\n-----END PRIVATE KEY-----\r\nnext",
			mustNotSee: []string{
				"very-secret",
				"BEGIN PRIVATE KEY",
			},
		},
		{
			name:  "rsa private key inline surroundings",
			input: "prefix -----BEGIN RSA PRIVATE KEY-----\nbody\n-----END RSA PRIVATE KEY----- suffix",
			mustNotSee: []string{
				"body",
				"BEGIN RSA PRIVATE KEY",
			},
		},
		{
			name:       "aws key embedded",
			input:      "prefix-AKIA1234567890ABCDEF-suffix",
			mustNotSee: []string{"AKIA1234567890ABCDEF"},
		},
		{
			name:       "multiple secrets same line",
			input:      "password=one token=two secret=three",
			mustNotSee: []string{"one", "two", "three"},
		},
		{
			name:       "nested assignment in structured field",
			input:      "Description=password=service-secret",
			mustNotSee: []string{"service-secret"},
		},
		{
			name:       "case insensitive assignments",
			input:      "PASSWORD: Alpha TOKEN : 'Beta' Api_Secret = \"Gamma\"",
			mustNotSee: []string{"Alpha", "Beta", "Gamma"},
		},
		{
			name:       "punctuated unquoted values",
			input:      "password=p@ss:/+._- token=abc.def_ghi-jkl",
			mustNotSee: []string{"p@ss:/+._-", "abc.def_ghi-jkl"},
		},
		{
			name:       "jwt without bearer",
			input:      "cookie=eyJ0eXAiOiJKV1QifQ.eyJyb2xlIjoiYWRtaW4ifQ.c2lnbmF0dXJl",
			mustNotSee: []string{"eyJ0eXAiOiJKV1QifQ", "eyJyb2xlIjoiYWRtaW4ifQ", "c2lnbmF0dXJl"},
		},
		{
			name:       "jwt multiple",
			input:      "a eyJhIjoiYiJ9.eyJjIjoiZCJ9.signature b eyJ4IjoieSJ9.eyJ6IjoxfQ.sig",
			mustNotSee: []string{"eyJhIjoiYiJ9", "signature", "eyJ4IjoieSJ9"},
		},
		{
			name:       "secret at line ending",
			input:      "token=last-value\nhealthy=true",
			mustNotSee: []string{"last-value"},
		},
		{
			name:       "private key consumes full block only",
			input:      "keep\n-----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY-----\nkeep-too",
			mustNotSee: []string{"BEGIN EC PRIVATE KEY", "\nx\n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := String(tt.input)
			for _, secret := range tt.mustNotSee {
				if strings.Contains(got, secret) {
					t.Errorf("String() leaked %q in %q", secret, got)
				}
			}
		})
	}
}

func TestStringDoesNotRedactSensitiveWordSubstrings(t *testing.T) {
	t.Parallel()

	input := "secretary=alice tokenizer=ready passwordless=true tokenization=enabled"
	if got := String(input); got != input {
		t.Fatalf("String() = %q, want unchanged %q", got, input)
	}
}

func TestStringSensitiveKeyTruthTable(t *testing.T) {
	t.Parallel()

	sensitive := []string{
		"password",
		"passwd",
		"pwd",
		"secret",
		"secret_key",
		"client_secret",
		"token",
		"access_token",
		"auth_token",
		"api_key",
		"apiKey",
		"apikey",
		"private_key",
		"privatekey",
		"access_key",
		"accesskey",
		"credential",
		"credentials",
		"passphrase",
		"STRIPE_KEY",
		"DEPLOY_KEY",
		"SSH_KEY",
		"SENDGRID_KEY",
		"GPG_KEY",
		"MAILGUN_KEY",
		"SENTRY_KEY",
		"cookie",
		"sessionid",
		"AWS_SECRET_ACCESS_KEY",
		"X-Api-Key",
	}
	for _, key := range sensitive {
		t.Run("redacts_"+key, func(t *testing.T) {
			t.Parallel()
			input := key + "=sensitive-value"
			want := key + "=[REDACTED]"
			if got := String(input); got != want {
				t.Fatalf("String(%q) = %q, want %q", input, got, want)
			}
		})
	}

	benign := []string{
		"passwordless",
		"tokenizer",
		"tokenization",
		"secretary",
		"key",
		"primary_key",
		"foreign_key",
		"sort_key",
		"partition_key",
		"composite_key",
		"candidate_key",
		"surrogate_key",
		"natural_key",
		"range_key",
		"hash_key",
		"shard_key",
		"cluster_key",
		"clustering_key",
		"routing_key",
		"cache_key",
		"group_key",
		"dedup_key",
		"public_key",
		"idempotency_key",
		"key_name",
		"username",
		"host",
		"port",
		"path",
		"monkey",
		"keyboard",
	}
	for _, key := range benign {
		t.Run("preserves_"+key, func(t *testing.T) {
			t.Parallel()
			input := key + "=ordinary-value"
			if got := String(input); got != input {
				t.Fatalf("String(%q) = %q, want unchanged", input, got)
			}
		})
	}
}

func TestStringRedactsFlagValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		want       string
		mustNotSee string
	}{
		{name: "long password", input: "client --password hunter2 --verbose", want: "client --password [REDACTED] --verbose", mustNotSee: "hunter2"},
		{name: "short password", input: "client -p swordfish", want: "client -p [REDACTED]", mustNotSee: "swordfish"},
		{name: "long token quoted", input: `client --token "abc def"`, want: "client --token [REDACTED]", mustNotSee: "abc def"},
		{name: "long secret", input: "client --secret top-secret", want: "client --secret [REDACTED]", mustNotSee: "top-secret"},
		{name: "requirepass", input: "redis-server --requirepass 123456", want: "redis-server --requirepass [REDACTED]", mustNotSee: "123456"},
		{name: "api key", input: "client --api-key api-value", want: "client --api-key [REDACTED]", mustNotSee: "api-value"},
		{name: "access key underscore", input: "client --access_key=access-value", want: "client --access_key=[REDACTED]", mustNotSee: "access-value"},
		{name: "passphrase equals", input: "client --passphrase=phrase-value", want: "client --passphrase=[REDACTED]", mustNotSee: "phrase-value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := String(tt.input)
			if got != tt.want {
				t.Fatalf("String(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if strings.Contains(got, tt.mustNotSee) {
				t.Fatalf("String() leaked %q in %q", tt.mustNotSee, got)
			}
		})
	}
}

func TestStringKeyRecognitionOracle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "exact password", input: "password=h", want: "password=[REDACTED]"},
		{name: "uppercase password", input: "PASSWORD=h", want: "PASSWORD=[REDACTED]"},
		{name: "pascal token", input: "Token=h", want: "Token=[REDACTED]"},
		{name: "exact secret colon", input: "secret: h", want: "secret: [REDACTED]"},
		{name: "snake password", input: "db_password=h", want: "db_password=[REDACTED]"},
		{name: "snake secret", input: "secret_key=h", want: "secret_key=[REDACTED]"},
		{name: "kebab token", input: "X-Auth-Token: h", want: "X-Auth-Token: [REDACTED]"},
		{name: "kebab secret", input: "api-secret=h", want: "api-secret=[REDACTED]"},
		{name: "dot secret", input: "app.secret=h", want: "app.secret=[REDACTED]"},
		{name: "camel access token", input: "accessToken=h", want: "accessToken=[REDACTED]"},
		{name: "camel api secret", input: "apiSecret=h", want: "apiSecret=[REDACTED]"},
		{name: "camel secret key", input: "secretKey=h", want: "secretKey=[REDACTED]"},
		{name: "camel auth token", input: "authToken=h", want: "authToken=[REDACTED]"},
		{name: "camel refresh token", input: "refreshToken=h", want: "refreshToken=[REDACTED]"},
		{name: "camel client secret", input: "clientSecret=h", want: "clientSecret=[REDACTED]"},
		{name: "pascal secret key", input: "SecretKey=h", want: "SecretKey=[REDACTED]"},
		{name: "pascal password hash", input: "PasswordHash=h", want: "PasswordHash=[REDACTED]"},
		{name: "pascal token value", input: "TokenValue=h", want: "TokenValue=[REDACTED]"},
		{name: "pascal secret access key", input: "SecretAccessKey=h", want: "SecretAccessKey=[REDACTED]"},
		{name: "password flag", input: "--password h", want: "--password [REDACTED]"},
		{name: "short password flag", input: "-p h", want: "-p [REDACTED]"},
		{name: "token flag", input: "--token h", want: "--token [REDACTED]"},
		{
			name:  "pem",
			input: "-----BEGIN PRIVATE KEY-----\nprivate-body\n-----END PRIVATE KEY-----",
			want:  "[REDACTED PRIVATE KEY]",
		},
		{name: "akia", input: "key=AKIA1234567890ABCDEF", want: "key=[REDACTED]"},
		{
			name:  "jwt",
			input: "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
			want:  "jwt=[REDACTED]",
		},
		{
			name:  "multiple keys",
			input: "user=bob password=p token=t",
			want:  "user=bob password=[REDACTED] token=[REDACTED]",
		},
		{name: "secretary unchanged", input: "secretary: Jane", want: "secretary: Jane"},
		{name: "pascal secretary unchanged", input: "Secretary: Jane", want: "Secretary: Jane"},
		{name: "tokenizer unchanged", input: "tokenizer=fast", want: "tokenizer=fast"},
		{name: "pascal tokenizer unchanged", input: "Tokenizer=fast", want: "Tokenizer=fast"},
		{name: "passwordless unchanged", input: "passwordless: yes", want: "passwordless: yes"},
		{name: "user unchanged", input: "user=bob", want: "user=bob"},
		{name: "host unchanged", input: "host=db1", want: "host=db1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := String(tt.input); got != tt.want {
				t.Fatalf("String(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSplitKeyWords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key  string
		want []string
	}{
		{key: "password", want: []string{"password"}},
		{key: "db_password", want: []string{"db", "password"}},
		{key: "X-Auth-Token", want: []string{"X", "Auth", "Token"}},
		{key: "app.secret", want: []string{"app", "secret"}},
		{key: "accessToken", want: []string{"access", "Token"}},
		{key: "SecretAccessKey", want: []string{"Secret", "Access", "Key"}},
		{key: "APIKey", want: []string{"API", "Key"}},
		{key: "secretary", want: []string{"secretary"}},
		{key: "Tokenizer", want: []string{"Tokenizer"}},
	}

	for _, tt := range tests {
		got := splitKeyWords(tt.key)
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("splitKeyWords(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}
