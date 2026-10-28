// Named allowlists. Hosts starting with "." match the domain and every subdomain.
// Checked 2026-10; registries move CDNs now and then, so `--allow` covers the rest.
export const PRESETS = {
  npm: { hosts: ['registry.npmjs.org', 'registry.yarnpkg.com'], about: 'npm / yarn registry' },
  pypi: { hosts: ['pypi.org', 'files.pythonhosted.org'], about: 'pip / uv / poetry downloads' },
  github: {
    hosts: ['github.com', 'api.github.com', 'codeload.github.com', 'raw.githubusercontent.com',
      'objects.githubusercontent.com', 'release-assets.githubusercontent.com'],
    about: 'git clone/fetch over HTTPS, API, raw files, release downloads',
  },
  huggingface: { hosts: ['.huggingface.co', '.hf.co'], about: 'model and dataset downloads' },
  crates: { hosts: ['crates.io', 'static.crates.io', 'index.crates.io'], about: 'cargo' },
  go: { hosts: ['proxy.golang.org', 'sum.golang.org'], about: 'go modules' },
  anthropic: { hosts: ['api.anthropic.com'], about: 'Claude API' },
  openai: { hosts: ['api.openai.com'], about: 'OpenAI API' },
  ollama: { localPorts: [11434], about: 'local Ollama server (127.0.0.1:11434)' },
  lmstudio: { localPorts: [1234], about: 'local LM Studio server (127.0.0.1:1234)' },
};
