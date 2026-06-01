package credstore

import "context"

type plainYamlBackend struct{}

func (p *plainYamlBackend) Name() string { return "plain-yaml" }

func (p *plainYamlBackend) Available() error { return nil }

func (p *plainYamlBackend) Get(_ context.Context, _ string) (string, error) {
	return "", ErrNotFound
}

func (p *plainYamlBackend) Put(_ context.Context, _, _ string) error {
	return nil
}

func (p *plainYamlBackend) Delete(_ context.Context, _ string) error {
	return nil
}
